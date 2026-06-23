// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel teardown runtime evidence artifact schema and validation.
//!
//! Follow-up from #673 / PR #869 decision record
//! `docs/KERNEL_TEARDOWN_RUNTIME_EVIDENCE_DECISION.md`.
//!
//! This module defines the `kernel.teardown.no_work_after.v1` artifact
//! shape and a fail-closed validator that rejects unknown fields, missing
//! required fields, and inconsistent status/fail-closed-reasons
//! combinations.  It does not update claim registry status, generated
//! claim docs, workflow targets, or product behavior.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

pub const KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID: &str = "kernel.teardown.no_work_after.v1";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS: &str =
    "runtime-kernel-teardown-no-work-after-artifact";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_VERIFIER: &str =
    "tidefs-xtask validate-kernel-teardown-runtime-artifact";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TIER: &str = "mounted-kernel-vfs";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TARGET_ID: &str =
    "kernel-teardown-mounted-vfs";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER: &str = "full-kernel-no-daemon";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID: &str = "kernel-teardown-no-daemon";
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_VALIDATION_TIER: &str =
    KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TIER;
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_TARGET_ID: &str =
    KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TARGET_ID;
pub const KERNEL_TEARDOWN_NO_WORK_AFTER_ARTIFACT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Sub-structs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownPhase {
    pub phase: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalObservation {
    pub operation: String,
    pub expected_refusal: bool,
    pub observed_result: String,
    pub new_work_enqueued_or_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupOutcome {
    pub unmount: String,
    pub rmmod: String,
    pub reload_remount_probe: String,
    pub dmesg_state: String,
    pub remaining_tidefs_work_observations: String,
}

// ---------------------------------------------------------------------------
// Main artifact struct
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTeardownNoWorkAfterV1 {
    pub artifact_version: u32,
    pub generated_by: String,
    pub claim_id: String,
    pub evidence_class: String,

    // Workflow / run identity
    pub workflow_run_id: String,
    pub workflow_run_attempt: u32,
    pub workflow_name: String,
    pub workflow_job: String,

    // Source identity
    pub source_ref: String,
    pub source_sha: String,

    // Target / tier
    pub validation_tier: String,
    pub target_id: String,

    // Kernel / module identity
    pub kernel_release: String,
    pub module_name: String,
    pub module_digest: String,

    // Teardown phases
    pub teardown_phases: Vec<TeardownPhase>,

    // Trace sources
    pub workqueue_trace_source: String,
    pub workqueue_trace_artifact_path: String,
    pub workqueue_trace_digest: String,
    pub callback_trace_source: String,
    pub callback_trace_artifact_path: String,
    pub callback_trace_digest: String,

    // Post-final-teardown refusal observations
    pub post_final_teardown_refusal_observations: Vec<RefusalObservation>,

    // Cleanup outcome
    pub cleanup_outcome: CleanupOutcome,

    // Overall status
    pub status: String,

    // Fail-closed reasons (empty only for pass)
    pub fail_closed_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validator output types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelTeardownNoWorkAfterSummary {
    pub status: String,
    pub fail_closed_count: usize,
    pub phase_count: usize,
    pub refusal_observation_count: usize,
    pub target_id: String,
    pub source_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelTeardownNoWorkAfterError {
    failures: Vec<String>,
}

impl KernelTeardownNoWorkAfterError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for KernelTeardownNoWorkAfterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "kernel teardown no-work-after artifact validation failed:"
        )?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for KernelTeardownNoWorkAfterError {}

// ---------------------------------------------------------------------------
// Well-known phase names & status values
// ---------------------------------------------------------------------------

const REQUIRED_PHASES: &[&str] = &[
    "module_load",
    "mount",
    "pre_teardown_io",
    "begin_teardown",
    "final_teardown",
    "post_final_refusal_probe",
    "cleanup",
    "module_unload",
    "reload_probe",
];

const VALID_STATUSES: &[&str] = &["pass", "fail", "blocked", "no-result"];
const VALID_TIER_TARGET_PAIRS: &[(&str, &str)] = &[
    (
        KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TIER,
        KERNEL_TEARDOWN_NO_WORK_AFTER_MOUNTED_KERNEL_VFS_TARGET_ID,
    ),
    (
        KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER,
        KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID,
    ),
];

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/// Load and validate a kernel teardown no-work-after artifact from a JSON
/// file on disk.
pub fn validate_kernel_teardown_no_work_after_artifact_path(
    path: impl AsRef<Path>,
) -> Result<KernelTeardownNoWorkAfterSummary, KernelTeardownNoWorkAfterError> {
    let raw = fs::read_to_string(path.as_ref()).map_err(|e| KernelTeardownNoWorkAfterError {
        failures: vec![format!(
            "cannot read artifact at {}: {e}",
            path.as_ref().display()
        )],
    })?;
    validate_kernel_teardown_no_work_after_artifact_json(&raw)
}

/// Validate a kernel teardown no-work-after artifact from JSON bytes.
pub fn validate_kernel_teardown_no_work_after_artifact_json(
    json: &str,
) -> Result<KernelTeardownNoWorkAfterSummary, KernelTeardownNoWorkAfterError> {
    let artifact: KernelTeardownNoWorkAfterV1 =
        serde_json::from_str(json).map_err(|e| KernelTeardownNoWorkAfterError {
            failures: vec![format!("deserialization failed: {e}")],
        })?;

    let mut failures: Vec<String> = Vec::new();

    // --- artifact_version ---
    if artifact.artifact_version != KERNEL_TEARDOWN_NO_WORK_AFTER_ARTIFACT_VERSION {
        failures.push(format!(
            "artifact_version must be {}, got {}",
            KERNEL_TEARDOWN_NO_WORK_AFTER_ARTIFACT_VERSION, artifact.artifact_version
        ));
    }

    // --- generated_by ---
    if artifact.generated_by.is_empty() {
        failures.push("generated_by is required".into());
    }

    // --- claim_id ---
    if artifact.claim_id != KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID {
        failures.push(format!(
            "claim_id must be `{}`, got `{}`",
            KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID, artifact.claim_id
        ));
    }

    // --- evidence_class ---
    if artifact.evidence_class != KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS {
        failures.push(format!(
            "evidence_class must be `{}`, got `{}`",
            KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS, artifact.evidence_class
        ));
    }

    // --- workflow / run identity ---
    if artifact.workflow_run_id.is_empty() {
        failures.push("workflow_run_id is required".into());
    }
    if artifact.workflow_run_attempt == 0 {
        failures.push("workflow_run_attempt must be non-zero".into());
    }
    if artifact.workflow_name.is_empty() {
        failures.push("workflow_name is required".into());
    }
    if artifact.workflow_job.is_empty() {
        failures.push("workflow_job is required".into());
    }

    // --- source identity ---
    if artifact.source_ref.is_empty() {
        failures.push("source_ref is required".into());
    }
    if artifact.source_sha.is_empty() {
        failures.push("source_sha is required".into());
    }

    // --- validation tier / target id ---
    let validation_tier_known = VALID_TIER_TARGET_PAIRS
        .iter()
        .any(|(tier, _target)| artifact.validation_tier == *tier);
    if !validation_tier_known {
        failures.push(format!(
            "validation_tier must be one of {:?}, got `{}`",
            VALID_TIER_TARGET_PAIRS
                .iter()
                .map(|(tier, _target)| *tier)
                .collect::<Vec<_>>(),
            artifact.validation_tier
        ));
    }

    let target_id_known = VALID_TIER_TARGET_PAIRS
        .iter()
        .any(|(_tier, target)| artifact.target_id == *target);
    if !target_id_known {
        failures.push(format!(
            "target_id must be one of {:?}, got `{}`",
            VALID_TIER_TARGET_PAIRS
                .iter()
                .map(|(_tier, target)| *target)
                .collect::<Vec<_>>(),
            artifact.target_id
        ));
    }

    let tier_target_pair_valid = VALID_TIER_TARGET_PAIRS
        .iter()
        .any(|(tier, target)| artifact.validation_tier == *tier && artifact.target_id == *target);
    if validation_tier_known && target_id_known && !tier_target_pair_valid {
        failures.push(format!(
            "validation_tier `{}` and target_id `{}` are not an allowed pair",
            artifact.validation_tier, artifact.target_id
        ));
    }

    // --- kernel / module identity ---
    if artifact.kernel_release.is_empty() {
        failures.push("kernel_release is required".into());
    }
    if artifact.module_name.is_empty() {
        failures.push("module_name is required".into());
    }
    if artifact.module_digest.is_empty() {
        failures.push("module_digest is required".into());
    }

    // --- teardown phases ---
    if artifact.teardown_phases.is_empty() {
        failures.push("teardown_phases must be non-empty".into());
    } else {
        let seen: BTreeSet<&str> = artifact
            .teardown_phases
            .iter()
            .map(|p| p.phase.as_str())
            .collect();
        for &required in REQUIRED_PHASES {
            if !seen.contains(required) {
                failures.push(format!("required teardown phase `{required}` is missing"));
            }
        }
        for (i, phase) in artifact.teardown_phases.iter().enumerate() {
            if phase.phase.is_empty() {
                failures.push(format!("teardown_phases[{i}].phase is empty"));
            }
            if phase.status.is_empty() {
                failures.push(format!(
                    "teardown_phases[{i}].status is empty (phase={})",
                    phase.phase
                ));
            }
        }
    }

    // --- trace sources ---
    let trace_sources = [
        ("workqueue_trace_source", &artifact.workqueue_trace_source),
        (
            "workqueue_trace_artifact_path",
            &artifact.workqueue_trace_artifact_path,
        ),
        ("workqueue_trace_digest", &artifact.workqueue_trace_digest),
        ("callback_trace_source", &artifact.callback_trace_source),
        (
            "callback_trace_artifact_path",
            &artifact.callback_trace_artifact_path,
        ),
        ("callback_trace_digest", &artifact.callback_trace_digest),
    ];
    for (name, value) in &trace_sources {
        if value.is_empty() {
            failures.push(format!("{name} is required"));
        }
    }

    // --- refusal observations ---
    if artifact.post_final_teardown_refusal_observations.is_empty() {
        failures.push("post_final_teardown_refusal_observations must be non-empty".into());
    } else {
        for (i, obs) in artifact
            .post_final_teardown_refusal_observations
            .iter()
            .enumerate()
        {
            if obs.operation.is_empty() {
                failures.push(format!(
                    "post_final_teardown_refusal_observations[{i}].operation is empty"
                ));
            }
            if obs.observed_result.is_empty() {
                failures.push(format!(
                    "post_final_teardown_refusal_observations[{i}].observed_result is empty"
                ));
            }
        }
    }

    // --- cleanup outcome ---
    {
        let c = &artifact.cleanup_outcome;
        if c.unmount.is_empty() {
            failures.push("cleanup_outcome.unmount is required".into());
        }
        if c.rmmod.is_empty() {
            failures.push("cleanup_outcome.rmmod is required".into());
        }
        if c.reload_remount_probe.is_empty() {
            failures.push("cleanup_outcome.reload_remount_probe is required".into());
        }
        if c.dmesg_state.is_empty() {
            failures.push("cleanup_outcome.dmesg_state is required".into());
        }
        if c.remaining_tidefs_work_observations.is_empty() {
            failures.push("cleanup_outcome.remaining_tidefs_work_observations is required".into());
        }
    }

    // --- status ---
    if !VALID_STATUSES.contains(&artifact.status.as_str()) {
        failures.push(format!(
            "status must be one of {:?}, got `{}`",
            VALID_STATUSES, artifact.status
        ));
    }

    // --- fail-closed reasons ---
    if artifact.status == "pass" && !artifact.fail_closed_reasons.is_empty() {
        failures.push("fail_closed_reasons must be empty when status is `pass`".into());
    }
    if artifact.status != "pass" && artifact.fail_closed_reasons.is_empty() {
        failures.push(format!(
            "fail_closed_reasons must be non-empty when status is `{}`",
            artifact.status
        ));
    }

    if !failures.is_empty() {
        return Err(KernelTeardownNoWorkAfterError { failures });
    }

    Ok(KernelTeardownNoWorkAfterSummary {
        status: artifact.status,
        fail_closed_count: artifact.fail_closed_reasons.len(),
        phase_count: artifact.teardown_phases.len(),
        refusal_observation_count: artifact.post_final_teardown_refusal_observations.len(),
        target_id: artifact.target_id,
        source_ref: artifact.source_ref,
    })
}

// ---------------------------------------------------------------------------
// Tests (inline)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pass_json() -> String {
        r#"{
            "artifact_version": 1,
            "generated_by": "kernel-teardown-validation",
            "claim_id": "kernel.teardown.no_work_after.v1",
            "evidence_class": "runtime-kernel-teardown-no-work-after-artifact",
            "workflow_run_id": "1234567890",
            "workflow_run_attempt": 1,
            "workflow_name": "Kernel Teardown Validation",
            "workflow_job": "kernel teardown mounted vfs",
            "source_ref": "refs/heads/master",
            "source_sha": "abc123def456",
            "validation_tier": "mounted-kernel-vfs",
            "target_id": "kernel-teardown-mounted-vfs",
            "kernel_release": "6.8.0-tidefs+",
            "module_name": "tidefs",
            "module_digest": "sha256:deadbeef",
            "teardown_phases": [
                {"phase": "module_load", "status": "completed"},
                {"phase": "mount", "status": "completed"},
                {"phase": "pre_teardown_io", "status": "completed"},
                {"phase": "begin_teardown", "status": "completed"},
                {"phase": "final_teardown", "status": "completed"},
                {"phase": "post_final_refusal_probe", "status": "completed"},
                {"phase": "cleanup", "status": "completed"},
                {"phase": "module_unload", "status": "completed"},
                {"phase": "reload_probe", "status": "completed"}
            ],
            "workqueue_trace_source": "tracefs:/sys/kernel/debug/tracing/instances/tidefs_teardown/trace",
            "workqueue_trace_artifact_path": "traces/workqueue-trace.dat",
            "workqueue_trace_digest": "blake3:abc123",
            "callback_trace_source": "tracefs:/sys/kernel/debug/tracing/instances/tidefs_teardown/trace",
            "callback_trace_artifact_path": "traces/callback-trace.dat",
            "callback_trace_digest": "blake3:def456",
            "post_final_teardown_refusal_observations": [
                {
                    "operation": "write",
                    "expected_refusal": true,
                    "observed_result": "EIO",
                    "new_work_enqueued_or_started": false
                }
            ],
            "cleanup_outcome": {
                "unmount": "success",
                "rmmod": "success",
                "reload_remount_probe": "module reloaded and remounted successfully",
                "dmesg_state": "no TideFS warnings",
                "remaining_tidefs_work_observations": "none"
            },
            "status": "pass",
            "fail_closed_reasons": []
        }"#.to_string()
    }

    #[test]
    fn pass_artifact_validates() {
        let json = minimal_pass_json();
        let summary =
            validate_kernel_teardown_no_work_after_artifact_json(&json).expect("should pass");
        assert_eq!(summary.status, "pass");
        assert_eq!(summary.fail_closed_count, 0);
        assert_eq!(summary.phase_count, 9);
        assert_eq!(summary.refusal_observation_count, 1);
        assert_eq!(summary.target_id, "kernel-teardown-mounted-vfs");
        assert_eq!(summary.source_ref, "refs/heads/master");
    }

    #[test]
    fn missing_required_field_fails() {
        // Drop workflow_run_id entirely
        let json = r#"{
            "artifact_version": 1,
            "generated_by": "test",
            "claim_id": "kernel.teardown.no_work_after.v1",
            "evidence_class": "runtime-kernel-teardown-no-work-after-artifact"
        }"#;
        let err = validate_kernel_teardown_no_work_after_artifact_json(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workflow"),
            "should complain about missing workflow fields: {msg}"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val
            .as_object_mut()
            .unwrap()
            .insert("unknown_field".into(), serde_json::Value::Bool(true));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown") || msg.contains("unknown_field"),
            "should reject unknown field: {msg}"
        );
    }

    #[test]
    fn artifact_version_mismatch_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val
            .as_object_mut()
            .unwrap()
            .insert("artifact_version".into(), serde_json::json!(2));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("artifact_version"),
            "should complain about wrong artifact_version: {msg}"
        );
    }

    #[test]
    fn workflow_run_attempt_zero_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val
            .as_object_mut()
            .unwrap()
            .insert("workflow_run_attempt".into(), serde_json::json!(0));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workflow_run_attempt"),
            "should complain about zero workflow_run_attempt: {msg}"
        );
    }

    #[test]
    fn workflow_job_empty_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "workflow_job".into(),
            serde_json::Value::String(String::new()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workflow_job"),
            "should complain about empty workflow_job: {msg}"
        );
    }

    #[test]
    fn source_ref_empty_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "source_ref".into(),
            serde_json::Value::String(String::new()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("source_ref"),
            "should complain about empty source_ref: {msg}"
        );
    }

    #[test]
    fn target_id_mismatch_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "target_id".into(),
            serde_json::Value::String("wrong-target".into()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("target_id"),
            "should complain about wrong target_id: {msg}"
        );
    }

    #[test]
    fn tier_mismatch_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "validation_tier".into(),
            serde_json::Value::String("qemu-guest".into()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("validation_tier"),
            "should complain about wrong validation_tier: {msg}"
        );
    }

    #[test]
    fn module_digest_empty_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "module_digest".into(),
            serde_json::Value::String(String::new()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("module_digest"),
            "should complain about empty module_digest: {msg}"
        );
    }

    #[test]
    fn missing_teardown_phase_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        // Remove final_teardown from the phases array
        let phases = json_val
            .as_object_mut()
            .unwrap()
            .get_mut("teardown_phases")
            .unwrap()
            .as_array_mut()
            .unwrap();
        phases.retain(|p| p["phase"] != "final_teardown");
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("final_teardown"),
            "should complain about missing final_teardown phase: {msg}"
        );
    }

    #[test]
    fn missing_refusal_observations_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "post_final_teardown_refusal_observations".into(),
            serde_json::Value::Array(vec![]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("refusal") || msg.contains("non-empty"),
            "should complain about empty refusal observations: {msg}"
        );
    }

    #[test]
    fn missing_trace_fields_fail() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "workqueue_trace_source".into(),
            serde_json::Value::String(String::new()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workqueue_trace_source"),
            "should complain about empty workqueue_trace_source: {msg}"
        );
    }

    #[test]
    fn cleanup_unmount_empty_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val
            .as_object_mut()
            .unwrap()
            .get_mut("cleanup_outcome")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unmount".into(), serde_json::Value::String(String::new()));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unmount"),
            "should complain about empty cleanup unmount: {msg}"
        );
    }

    #[test]
    fn fail_status_without_reasons_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let obj = json_val.as_object_mut().unwrap();
        obj.insert("status".into(), serde_json::Value::String("fail".into()));
        obj.insert(
            "fail_closed_reasons".into(),
            serde_json::Value::Array(vec![]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fail_closed_reasons"),
            "should complain about empty fail_closed_reasons on fail: {msg}"
        );
    }

    #[test]
    fn pass_status_with_reasons_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let obj = json_val.as_object_mut().unwrap();
        obj.insert(
            "fail_closed_reasons".into(),
            serde_json::json!(["some reason"]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("fail_closed_reasons"),
            "should complain about non-empty fail_closed_reasons on pass: {msg}"
        );
    }

    #[test]
    fn blocked_status_with_reasons_passes() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let obj = json_val.as_object_mut().unwrap();
        obj.insert("status".into(), serde_json::Value::String("blocked".into()));
        obj.insert(
            "fail_closed_reasons".into(),
            serde_json::json!(["post-final-teardown work enqueued"]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let summary =
            validate_kernel_teardown_no_work_after_artifact_json(&json).expect("should pass");
        assert_eq!(summary.status, "blocked");
        assert_eq!(summary.fail_closed_count, 1);
    }

    #[test]
    fn no_result_status_with_reasons_passes() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let obj = json_val.as_object_mut().unwrap();
        obj.insert(
            "status".into(),
            serde_json::Value::String("no-result".into()),
        );
        obj.insert(
            "fail_closed_reasons".into(),
            serde_json::json!(["harness timeout before teardown"]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let summary =
            validate_kernel_teardown_no_work_after_artifact_json(&json).expect("should pass");
        assert_eq!(summary.status, "no-result");
        assert_eq!(summary.fail_closed_count, 1);
    }

    #[test]
    fn invalid_status_rejected() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let obj = json_val.as_object_mut().unwrap();
        obj.insert("status".into(), serde_json::Value::String("unknown".into()));
        obj.insert("fail_closed_reasons".into(), serde_json::json!(["reason"]));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("status"),
            "should reject invalid status: {msg}"
        );
    }

    #[test]
    fn constants_are_non_empty() {
        assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID.is_empty());
        assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS.is_empty());
        assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_VERIFIER.is_empty());
    }

    #[test]
    fn missing_module_name_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "module_name".into(),
            serde_json::Value::String(String::new()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("module_name"),
            "should complain about empty module_name: {msg}"
        );
    }

    #[test]
    fn claim_id_mismatch_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "claim_id".into(),
            serde_json::Value::String("wrong.claim.v1".into()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("claim_id"),
            "should complain about wrong claim_id: {msg}"
        );
    }

    #[test]
    fn evidence_class_mismatch_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "evidence_class".into(),
            serde_json::Value::String("wrong-class".into()),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("evidence_class"),
            "should complain about wrong evidence_class: {msg}"
        );
    }

    #[test]
    fn refusal_observation_missing_operation_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        json_val.as_object_mut().unwrap().insert(
            "post_final_teardown_refusal_observations".into(),
            serde_json::json!([{
                "operation": "",
                "expected_refusal": true,
                "observed_result": "EIO",
                "new_work_enqueued_or_started": false
            }]),
        );
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("operation"),
            "should complain about empty operation in refusal observation: {msg}"
        );
    }

    #[test]
    fn teardown_phase_empty_status_fails() {
        let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
        let phases = json_val
            .as_object_mut()
            .unwrap()
            .get_mut("teardown_phases")
            .unwrap()
            .as_array_mut()
            .unwrap();
        // Corrupt the first phase's status
        phases[0]
            .as_object_mut()
            .unwrap()
            .insert("status".into(), serde_json::Value::String(String::new()));
        let json = serde_json::to_string_pretty(&json_val).unwrap();
        let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("status"),
            "should complain about empty phase status: {msg}"
        );
    }

    /// Round-trip test: serialize a pass artifact and validate the resulting JSON.
    #[test]
    fn roundtrip_serialize_and_validate() {
        let artifact = KernelTeardownNoWorkAfterV1 {
            artifact_version: 1,
            generated_by: "test".into(),
            claim_id: KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID.into(),
            evidence_class: KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS.into(),
            workflow_run_id: "1".into(),
            workflow_run_attempt: 1,
            workflow_name: "test".into(),
            workflow_job: "kernel teardown mounted vfs".into(),
            source_ref: "refs/heads/test".into(),
            source_sha: "abc".into(),
            validation_tier: "mounted-kernel-vfs".into(),
            target_id: "kernel-teardown-mounted-vfs".into(),
            kernel_release: "6.8".into(),
            module_name: "tidefs".into(),
            module_digest: "sha256:abc".into(),
            teardown_phases: REQUIRED_PHASES
                .iter()
                .map(|&p| TeardownPhase {
                    phase: p.into(),
                    status: "completed".into(),
                    start_timestamp: None,
                    end_timestamp: None,
                    notes: None,
                })
                .collect(),
            workqueue_trace_source: "tracefs:...".into(),
            workqueue_trace_artifact_path: "wq.dat".into(),
            workqueue_trace_digest: "blake3:abc".into(),
            callback_trace_source: "tracefs:...".into(),
            callback_trace_artifact_path: "cb.dat".into(),
            callback_trace_digest: "blake3:def".into(),
            post_final_teardown_refusal_observations: vec![RefusalObservation {
                operation: "read".into(),
                expected_refusal: true,
                observed_result: "EIO".into(),
                new_work_enqueued_or_started: false,
            }],
            cleanup_outcome: CleanupOutcome {
                unmount: "ok".into(),
                rmmod: "ok".into(),
                reload_remount_probe: "ok".into(),
                dmesg_state: "clean".into(),
                remaining_tidefs_work_observations: "none".into(),
            },
            status: "pass".into(),
            fail_closed_reasons: vec![],
        };
        let json = serde_json::to_string_pretty(&artifact).unwrap();
        let summary = validate_kernel_teardown_no_work_after_artifact_json(&json)
            .expect("round-trip should pass");
        assert_eq!(summary.status, "pass");
        assert_eq!(summary.phase_count, REQUIRED_PHASES.len());
    }
}
