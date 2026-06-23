// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for the kernel teardown no-work-after artifact
//! schema and validator.
//!
//! These tests exercise the public API from crate-external perspective,
//! complementing the inline unit tests in the module source.

use tidefs_validation::kernel_teardown_evidence::{
    validate_kernel_teardown_no_work_after_artifact_json,
    KERNEL_TEARDOWN_NO_WORK_AFTER_ARTIFACT_VERSION, KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS,
    KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER,
    KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID, KERNEL_TEARDOWN_NO_WORK_AFTER_TARGET_ID,
    KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID, KERNEL_TEARDOWN_NO_WORK_AFTER_VALIDATION_TIER,
    KERNEL_TEARDOWN_NO_WORK_AFTER_VERIFIER,
};

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

fn no_daemon_pass_json() -> String {
    let mut value: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.insert(
        "validation_tier".into(),
        serde_json::Value::String(KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER.into()),
    );
    obj.insert(
        "target_id".into(),
        serde_json::Value::String(KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID.into()),
    );
    serde_json::to_string_pretty(&value).unwrap()
}

// ── Passthrough validation ───────────────────────────────────────────────

#[test]
fn integration_pass_artifact_validates() {
    let json = minimal_pass_json();
    let summary = validate_kernel_teardown_no_work_after_artifact_json(&json)
        .expect("pass artifact should validate");
    assert_eq!(summary.status, "pass");
    assert_eq!(summary.fail_closed_count, 0);
    assert_eq!(summary.phase_count, 9);
    assert_eq!(summary.refusal_observation_count, 1);
    assert_eq!(summary.target_id, KERNEL_TEARDOWN_NO_WORK_AFTER_TARGET_ID);
    assert_eq!(summary.source_ref, "refs/heads/master");
}

#[test]
fn integration_full_kernel_no_daemon_artifact_validates() {
    let json = no_daemon_pass_json();
    let summary = validate_kernel_teardown_no_work_after_artifact_json(&json)
        .expect("full-kernel-no-daemon artifact should validate");
    assert_eq!(summary.status, "pass");
    assert_eq!(
        summary.target_id,
        KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID
    );
}

// ── Missing required field ───────────────────────────────────────────────

#[test]
fn integration_missing_workflow_run_id_fails() {
    // Omit everything except header fields
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
        "should mention missing workflow fields: {msg}"
    );
}

#[test]
fn integration_missing_claim_id_fails() {
    let json = r#"{
        "artifact_version": 1,
        "generated_by": "test",
        "claim_id": "",
        "evidence_class": "runtime-kernel-teardown-no-work-after-artifact",
        "workflow_run_id": "1",
        "workflow_run_attempt": 1,
        "workflow_name": "test",
        "workflow_job": "kernel teardown mounted vfs",
        "source_ref": "ref",
        "source_sha": "abc",
        "validation_tier": "mounted-kernel-vfs",
        "target_id": "kernel-teardown-mounted-vfs",
        "kernel_release": "6.8",
        "module_name": "tidefs",
        "module_digest": "sha256:abc",
        "teardown_phases": [],
        "workqueue_trace_source": "a",
        "workqueue_trace_artifact_path": "a",
        "workqueue_trace_digest": "a",
        "callback_trace_source": "a",
        "callback_trace_artifact_path": "a",
        "callback_trace_digest": "a",
        "post_final_teardown_refusal_observations": [
            {"operation": "w", "expected_refusal": true, "observed_result": "EIO", "new_work_enqueued_or_started": false}
        ],
        "cleanup_outcome": {
            "unmount": "ok", "rmmod": "ok", "reload_remount_probe": "ok",
            "dmesg_state": "ok", "remaining_tidefs_work_observations": "ok"
        },
        "status": "pass",
        "fail_closed_reasons": []
    }"#;
    let err = validate_kernel_teardown_no_work_after_artifact_json(json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("claim_id"),
        "should reject empty claim_id: {msg}"
    );
}

// ── Unknown field ────────────────────────────────────────────────────────

#[test]
fn integration_unknown_field_rejected() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    json_val
        .as_object_mut()
        .unwrap()
        .insert("extra_junk".into(), serde_json::Value::Bool(true));
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unknown") || msg.contains("extra_junk"),
        "should reject unknown field: {msg}"
    );
}

// ── Source/target/tier mismatch ──────────────────────────────────────────

#[test]
fn integration_artifact_version_mismatch_fails() {
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
        "should reject wrong artifact_version: {msg}"
    );
}

#[test]
fn integration_empty_source_ref_fails() {
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
        "should reject empty source_ref: {msg}"
    );
}

#[test]
fn integration_target_id_mismatch_fails() {
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
        "should reject wrong target_id: {msg}"
    );
}

#[test]
fn integration_validation_tier_mismatch_fails() {
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
        "should reject wrong validation_tier: {msg}"
    );
}

#[test]
fn integration_tier_target_pair_mismatch_fails() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    json_val.as_object_mut().unwrap().insert(
        "validation_tier".into(),
        serde_json::Value::String(KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER.into()),
    );
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("allowed pair"),
        "should reject mismatched tier/target pair: {msg}"
    );
}

// ── Trace / refusal omission ─────────────────────────────────────────────

#[test]
fn integration_missing_workqueue_trace_fails() {
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
        "should reject empty workqueue_trace_source: {msg}"
    );
}

#[test]
fn integration_missing_callback_trace_fails() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    json_val.as_object_mut().unwrap().insert(
        "callback_trace_source".into(),
        serde_json::Value::String(String::new()),
    );
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("callback_trace_source"),
        "should reject empty callback_trace_source: {msg}"
    );
}

#[test]
fn integration_newline_only_trace_digest_fails() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    json_val.as_object_mut().unwrap().insert(
        "workqueue_trace_digest".into(),
        serde_json::Value::String(
            "blake3:295192ea1ec8566d563b1a7587e5f0198580cdbd043842f5090a4c197c20c67a".into(),
        ),
    );
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("empty trace digest"),
        "should reject newline-only trace digest: {msg}"
    );
}

#[test]
fn integration_empty_refusal_observations_fails() {
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
        "should reject empty refusal observations: {msg}"
    );
}

// ── Cleanup failure ──────────────────────────────────────────────────────

#[test]
fn integration_cleanup_unmount_empty_fails() {
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
        "should reject empty cleanup.unmount: {msg}"
    );
}

#[test]
fn integration_cleanup_rmmod_empty_fails() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    json_val
        .as_object_mut()
        .unwrap()
        .get_mut("cleanup_outcome")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("rmmod".into(), serde_json::Value::String(String::new()));
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("rmmod"),
        "should reject empty cleanup.rmmod: {msg}"
    );
}

// ── Fail-closed status cases ─────────────────────────────────────────────

#[test]
fn integration_pass_with_reasons_fails() {
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
        "pass with non-empty fail_closed_reasons should fail: {msg}"
    );
}

#[test]
fn integration_fail_without_reasons_fails() {
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
        "fail without reasons should fail: {msg}"
    );
}

#[test]
fn integration_blocked_with_reasons_passes() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    let obj = json_val.as_object_mut().unwrap();
    obj.insert("status".into(), serde_json::Value::String("blocked".into()));
    obj.insert(
        "fail_closed_reasons".into(),
        serde_json::json!(["post-final-teardown work enqueued"]),
    );
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let summary = validate_kernel_teardown_no_work_after_artifact_json(&json)
        .expect("blocked with reasons should pass");
    assert_eq!(summary.status, "blocked");
    assert_eq!(summary.fail_closed_count, 1);
}

// ── Constant sanity ──────────────────────────────────────────────────────

#[test]
fn integration_constants_are_non_empty() {
    assert_eq!(KERNEL_TEARDOWN_NO_WORK_AFTER_ARTIFACT_VERSION, 1);
    assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_V1_CLAIM_ID.is_empty());
    assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_EVIDENCE_CLASS.is_empty());
    assert_eq!(
        KERNEL_TEARDOWN_NO_WORK_AFTER_VALIDATION_TIER,
        "mounted-kernel-vfs"
    );
    assert_eq!(
        KERNEL_TEARDOWN_NO_WORK_AFTER_TARGET_ID,
        "kernel-teardown-mounted-vfs"
    );
    assert_eq!(
        KERNEL_TEARDOWN_NO_WORK_AFTER_FULL_KERNEL_NO_DAEMON_TIER,
        "full-kernel-no-daemon"
    );
    assert_eq!(
        KERNEL_TEARDOWN_NO_WORK_AFTER_NO_DAEMON_TARGET_ID,
        "kernel-teardown-no-daemon"
    );
    assert!(!KERNEL_TEARDOWN_NO_WORK_AFTER_VERIFIER.is_empty());
}

// ── Invalid status ───────────────────────────────────────────────────────

#[test]
fn integration_invalid_status_rejected() {
    let mut json_val: serde_json::Value = serde_json::from_str(&minimal_pass_json()).unwrap();
    let obj = json_val.as_object_mut().unwrap();
    obj.insert("status".into(), serde_json::Value::String("bogus".into()));
    obj.insert("fail_closed_reasons".into(), serde_json::json!(["reason"]));
    let json = serde_json::to_string_pretty(&json_val).unwrap();
    let err = validate_kernel_teardown_no_work_after_artifact_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("status"), "should reject bogus status: {msg}");
}
