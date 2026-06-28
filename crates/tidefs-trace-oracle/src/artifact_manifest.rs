// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reviewable artifact manifests for trace replay and comparison outputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tidefs_types_vfs_core::TIDE_CONTRACT_VERSION_V1;

use crate::backend::{
    BackendStep, TraceComparison, TraceOperation, BACKEND_LOCAL_RUNTIME, BACKEND_MODEL,
};
use crate::protocol::{
    CLUSTER_TRACE_SCHEMA, KEY_SCHEMA, KEY_VERSION, OP_TRACE_META, POOL_TRACE_SCHEMA, TRACE_VERSION,
};
use crate::{load_trace, sha256_file, TraceError};

pub const TRACE_ARTIFACT_SCHEMA_VERSION: u64 = 1;
pub const TRACE_ARTIFACT_BACKEND_COMPARE: &str = "compare";
pub const VALIDATION_TIER_SOURCE_MODEL: &str = "source-model";
pub const VALIDATION_TIER_HARNESS_ONLY: &str = "harness-only";
pub const EVIDENCE_CLASS_MODEL_ONLY: &str = "model-only";
pub const EVIDENCE_CLASS_HARNESS_ONLY: &str = "harness-only";
pub const EVIDENCE_CLASS_RUNTIME: &str = "runtime";
pub const RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE: &str = "mounted_userspace";
pub const RUNTIME_TRACE_BACKEND_QEMU_GUEST: &str = "qemu_guest";
pub const RUNTIME_TRACE_BACKEND_MOUNTED_KERNEL_VFS: &str = "mounted_kernel_vfs";
pub const RUNTIME_TRACE_BACKEND_KERNEL_BLOCK_IO: &str = "kernel_block_io";
pub const RUNTIME_TRACE_BACKEND_FULL_KERNEL_NO_DAEMON: &str = "full_kernel_no_daemon";
pub const RUNTIME_TRACE_BACKEND_MULTI_PROCESS_DISTRIBUTED: &str = "multi_process_distributed";

const MODEL_ONLY_NOTES: &str = "Model-only trace artifact. Validates deterministic contract replay through tidefs-model-core. Insufficient for runtime crash claims; runtime crash evidence requires a mounted backend with crash injection, recovery logs, and a CI artifact reference.";
const HARNESS_ONLY_NOTES: &str = "Model/local-runtime comparison artifact from the local trace-oracle harness. This is harness-only tooling evidence, not mounted runtime or crash-safety evidence; runtime claim closure requires a future mounted crash/recovery artifact with a CI artifact reference.";
const RUNTIME_NOTES: &str = "Runtime trace comparison artifact. The runtime event stream came from a mounted/runtime backend and carries GitHub Actions artifact metadata. Claim closure still requires a registered claim id and claims-gate review.";

/// Top-level trace artifact manifest schema, version 1.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TraceArtifactManifest {
    pub artifact_schema_version: u64,
    pub trace_schema: String,
    pub trace_version: u64,
    pub request_contract_version: u64,
    pub backend: String,
    pub environment_model: String,
    pub validation_tier: String,
    pub evidence_class: String,
    pub generated_at: String,
    pub generated_by: String,
    pub input: TraceArtifactInput,
    pub output: TraceArtifactOutput,
    pub claims_covered: Vec<String>,
    pub ci_artifact_ref: Option<String>,
    pub ci_run_url: Option<String>,
    pub notes: String,
}

/// Input trace descriptor recorded in an artifact manifest.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TraceArtifactInput {
    pub trace_path: String,
    pub trace_digest_sha256: String,
    pub trace_op_count: u64,
    pub trace_descriptor: String,
}

/// Output replay or comparison descriptor recorded in an artifact manifest.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TraceArtifactOutput {
    pub events_digest_sha256: String,
    pub final_fingerprint: String,
    pub event_count: u64,
    pub mismatches: u64,
    pub result: String,
}

/// Parsed and validated trace metadata used to construct artifact manifests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceArtifactInputDescriptor {
    pub trace_schema: String,
    pub trace_version: u64,
    pub input: TraceArtifactInput,
}

/// Metadata required before a trace comparison can be classified as runtime evidence.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuntimeTraceArtifactMetadata {
    pub runtime_backend: String,
    pub validation_tier: String,
    pub ci_artifact_ref: String,
    pub ci_run_url: String,
    #[serde(default)]
    pub claims_covered: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

impl TraceArtifactManifest {
    /// Build a model-only replay manifest from one model backend event stream.
    pub fn model_replay(
        trace_path: &Path,
        trace_path_label: impl Into<String>,
        trace_descriptor: impl Into<String>,
        events: &[BackendStep],
        result: ArtifactRunResult,
        generated_at: impl Into<String>,
    ) -> Result<Self, TraceError> {
        let descriptor =
            describe_trace_input(trace_path, trace_path_label, trace_descriptor.into())?;
        Ok(Self {
            artifact_schema_version: TRACE_ARTIFACT_SCHEMA_VERSION,
            trace_schema: descriptor.trace_schema,
            trace_version: descriptor.trace_version,
            request_contract_version: u64::from(TIDE_CONTRACT_VERSION_V1.raw()),
            backend: BACKEND_MODEL.into(),
            environment_model: "tidefs-model-core".into(),
            validation_tier: VALIDATION_TIER_SOURCE_MODEL.into(),
            evidence_class: EVIDENCE_CLASS_MODEL_ONLY.into(),
            generated_at: generated_at.into(),
            generated_by: generated_by(),
            input: descriptor.input,
            output: TraceArtifactOutput {
                events_digest_sha256: digest_backend_steps(events)?,
                final_fingerprint: final_backend_fingerprint(events),
                event_count: events.len() as u64,
                mismatches: 0,
                result: result.label().into(),
            },
            claims_covered: Vec::new(),
            ci_artifact_ref: None,
            ci_run_url: None,
            notes: MODEL_ONLY_NOTES.into(),
        })
    }

    /// Build a harness-only model/local-runtime comparison manifest.
    pub fn local_comparison(
        comparison: &TraceComparison,
        trace_path_label: impl Into<String>,
        trace_descriptor: impl Into<String>,
        generated_at: impl Into<String>,
    ) -> Result<Self, TraceError> {
        let descriptor = describe_trace_input(
            &comparison.trace_path,
            trace_path_label,
            trace_descriptor.into(),
        )?;
        let output_result = if comparison.passed() {
            ArtifactRunResult::Pass
        } else {
            ArtifactRunResult::Fail
        };
        Ok(Self {
            artifact_schema_version: TRACE_ARTIFACT_SCHEMA_VERSION,
            trace_schema: descriptor.trace_schema,
            trace_version: descriptor.trace_version,
            request_contract_version: u64::from(TIDE_CONTRACT_VERSION_V1.raw()),
            backend: TRACE_ARTIFACT_BACKEND_COMPARE.into(),
            environment_model: "runtime".into(),
            validation_tier: VALIDATION_TIER_HARNESS_ONLY.into(),
            evidence_class: EVIDENCE_CLASS_HARNESS_ONLY.into(),
            generated_at: generated_at.into(),
            generated_by: generated_by(),
            input: descriptor.input,
            output: TraceArtifactOutput {
                events_digest_sha256: digest_backend_steps(
                    comparison
                        .model_events
                        .iter()
                        .chain(comparison.runtime_events.iter()),
                )?,
                final_fingerprint: comparison
                    .final_fingerprint(BACKEND_LOCAL_RUNTIME)
                    .or_else(|| comparison.final_fingerprint(BACKEND_MODEL))
                    .unwrap_or("")
                    .to_string(),
                event_count: (comparison.model_events.len() + comparison.runtime_events.len())
                    as u64,
                mismatches: comparison.mismatches.len() as u64,
                result: output_result.label().into(),
            },
            claims_covered: Vec::new(),
            ci_artifact_ref: None,
            ci_run_url: None,
            notes: HARNESS_ONLY_NOTES.into(),
        })
    }

    /// Build a runtime comparison manifest from mounted/runtime backend events.
    pub fn runtime_comparison(
        comparison: &TraceComparison,
        trace_path_label: impl Into<String>,
        trace_descriptor: impl Into<String>,
        runtime: RuntimeTraceArtifactMetadata,
        generated_at: impl Into<String>,
    ) -> Result<Self, TraceError> {
        validate_runtime_metadata(&runtime)?;
        validate_runtime_backend_events(comparison, &runtime.runtime_backend)?;
        let trace_path_label = trace_path_label.into();
        validate_runtime_trace_path_label(&trace_path_label)?;
        let descriptor = describe_trace_input(
            &comparison.trace_path,
            trace_path_label,
            trace_descriptor.into(),
        )?;
        let output_result = if comparison.passed() {
            ArtifactRunResult::Pass
        } else {
            ArtifactRunResult::Fail
        };
        let notes = if runtime.notes.trim().is_empty() {
            RUNTIME_NOTES.into()
        } else {
            runtime.notes
        };
        Ok(Self {
            artifact_schema_version: TRACE_ARTIFACT_SCHEMA_VERSION,
            trace_schema: descriptor.trace_schema,
            trace_version: descriptor.trace_version,
            request_contract_version: u64::from(TIDE_CONTRACT_VERSION_V1.raw()),
            backend: TRACE_ARTIFACT_BACKEND_COMPARE.into(),
            environment_model: "runtime".into(),
            validation_tier: runtime.validation_tier,
            evidence_class: EVIDENCE_CLASS_RUNTIME.into(),
            generated_at: generated_at.into(),
            generated_by: generated_by(),
            input: descriptor.input,
            output: TraceArtifactOutput {
                events_digest_sha256: digest_backend_steps(
                    comparison
                        .model_events
                        .iter()
                        .chain(comparison.runtime_events.iter()),
                )?,
                final_fingerprint: final_backend_fingerprint(&comparison.runtime_events),
                event_count: (comparison.model_events.len() + comparison.runtime_events.len())
                    as u64,
                mismatches: comparison.mismatches.len() as u64,
                result: output_result.label().into(),
            },
            claims_covered: runtime.claims_covered,
            ci_artifact_ref: Some(runtime.ci_artifact_ref),
            ci_run_url: Some(runtime.ci_run_url),
            notes,
        })
    }

    /// Write the manifest as pretty JSON with a trailing newline.
    pub fn write_json_file(&self, path: &Path) -> Result<(), TraceError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{json}\n"))?;
        Ok(())
    }
}

/// Artifact-level replay/comparison result label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactRunResult {
    Pass,
    Fail,
    Skipped,
}

impl ArtifactRunResult {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ArtifactRunResult::Pass => "pass",
            ArtifactRunResult::Fail => "fail",
            ArtifactRunResult::Skipped => "skipped",
        }
    }
}

/// Validate trace metadata and compute input digest/op-count fields.
pub fn describe_trace_input(
    trace_path: &Path,
    trace_path_label: impl Into<String>,
    trace_descriptor: String,
) -> Result<TraceArtifactInputDescriptor, TraceError> {
    if trace_descriptor.trim().is_empty() {
        return Err(TraceError::Protocol(
            "trace artifact descriptor must not be empty".into(),
        ));
    }
    let ops = load_trace(trace_path)?;
    if ops.is_empty() {
        return Err(TraceError::Protocol("trace file is empty".into()));
    }
    let first = ops.first().expect("checked non-empty trace");
    let meta: TraceOperation = serde_json::from_value(first.clone())?;
    if meta.op != OP_TRACE_META {
        return Err(TraceError::Protocol(
            "trace_meta must be first op for artifact manifest".into(),
        ));
    }
    let schema = required_meta_string(&meta.args, KEY_SCHEMA)?;
    if schema != POOL_TRACE_SCHEMA && schema != CLUSTER_TRACE_SCHEMA {
        return Err(TraceError::Protocol(format!(
            "unsupported schema: {schema}"
        )));
    }
    let version = required_meta_u64(&meta.args, KEY_VERSION)?;
    if version == 0 || version > TRACE_VERSION {
        return Err(TraceError::Protocol(format!(
            "unsupported version: {version}"
        )));
    }
    Ok(TraceArtifactInputDescriptor {
        trace_schema: schema,
        trace_version: version,
        input: TraceArtifactInput {
            trace_path: trace_path_label.into(),
            trace_digest_sha256: sha256_file(trace_path)?,
            trace_op_count: ops.len() as u64,
            trace_descriptor,
        },
    })
}

/// Current UTC timestamp formatted as an ISO 8601/RFC3339 string.
#[must_use]
pub fn generated_at_now_utc() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    format_unix_seconds_utc(seconds)
}

/// Tool/version string for manifests emitted by this crate.
#[must_use]
pub fn generated_by() -> String {
    format!("tidefs-trace-oracle {}", env!("CARGO_PKG_VERSION"))
}

/// Resolve the default artifact directory without dirtying committed traces.
#[must_use]
pub fn default_artifact_dir(repo_root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("target"))
        .join("trace-oracle-artifacts")
}

/// Deterministic manifest path for a trace descriptor and backend label.
#[must_use]
pub fn default_manifest_path(repo_root: &Path, trace_descriptor: &str, backend: &str) -> PathBuf {
    default_artifact_dir(repo_root).join(format!(
        "{}.{}.manifest.json",
        sanitize_artifact_id(trace_descriptor),
        sanitize_artifact_id(backend)
    ))
}

/// Convert a path-like descriptor into a stable artifact id.
#[must_use]
pub fn sanitize_artifact_id(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in input.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash {
                out.push(mapped);
            }
            last_dash = true;
        } else {
            out.push(mapped);
            last_dash = false;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "trace".into()
    } else {
        trimmed.into()
    }
}

fn required_meta_string(args: &Value, key: &str) -> Result<String, TraceError> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| TraceError::Protocol(format!("trace_meta missing string {key}")))
}

fn required_meta_u64(args: &Value, key: &str) -> Result<u64, TraceError> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| TraceError::Protocol(format!("trace_meta missing numeric {key}")))
}

fn validate_runtime_metadata(runtime: &RuntimeTraceArtifactMetadata) -> Result<(), TraceError> {
    if !is_runtime_trace_backend(&runtime.runtime_backend) {
        return Err(TraceError::Protocol(format!(
            "runtime trace backend `{}` is not a mounted/runtime backend",
            runtime.runtime_backend
        )));
    }
    if !is_runtime_validation_tier(&runtime.validation_tier) {
        return Err(TraceError::Protocol(format!(
            "validation tier `{}` is not a runtime tier",
            runtime.validation_tier
        )));
    }
    if !is_safe_ci_artifact_ref(&runtime.ci_artifact_ref) {
        return Err(TraceError::Protocol(
            "runtime trace manifest requires a safe GitHub Actions artifact name".into(),
        ));
    }
    if !is_safe_ci_run_url(&runtime.ci_run_url) {
        return Err(TraceError::Protocol(
            "runtime trace manifest requires a tidefs/tidefs GitHub Actions run URL".into(),
        ));
    }
    Ok(())
}

fn validate_runtime_backend_events(
    comparison: &TraceComparison,
    runtime_backend: &str,
) -> Result<(), TraceError> {
    if comparison.runtime_events.is_empty() {
        return Err(TraceError::Protocol(
            "runtime trace manifest requires runtime backend events".into(),
        ));
    }
    if comparison
        .runtime_events
        .iter()
        .any(|event| event.backend != runtime_backend)
    {
        return Err(TraceError::Protocol(format!(
            "runtime trace manifest requires all runtime events to use mounted/runtime backend `{runtime_backend}`"
        )));
    }
    Ok(())
}

fn validate_runtime_trace_path_label(trace_path_label: &str) -> Result<(), TraceError> {
    if trace_path_label.trim().is_empty() {
        return Err(TraceError::Protocol(
            "runtime trace manifest requires a reviewable trace path label".into(),
        ));
    }
    if trace_path_label.contains('\\') || trace_path_label.contains("..") {
        return Err(TraceError::Protocol(
            "runtime trace path label must not contain runner-local path components".into(),
        ));
    }
    let path = Path::new(trace_path_label);
    if path.is_absolute() {
        return Err(TraceError::Protocol(
            "runtime trace path label must be relative, not runner-local absolute path".into(),
        ));
    }
    if trace_path_label.contains("ghp_") || trace_path_label.contains("github_pat") {
        return Err(TraceError::Protocol(
            "runtime trace path label must not contain token material".into(),
        ));
    }
    Ok(())
}

fn is_runtime_trace_backend(value: &str) -> bool {
    matches!(
        value,
        RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE
            | RUNTIME_TRACE_BACKEND_QEMU_GUEST
            | RUNTIME_TRACE_BACKEND_MOUNTED_KERNEL_VFS
            | RUNTIME_TRACE_BACKEND_KERNEL_BLOCK_IO
            | RUNTIME_TRACE_BACKEND_FULL_KERNEL_NO_DAEMON
            | RUNTIME_TRACE_BACKEND_MULTI_PROCESS_DISTRIBUTED
    )
}

fn is_runtime_validation_tier(value: &str) -> bool {
    matches!(
        value,
        "mounted-userspace"
            | "qemu-guest"
            | "mounted-kernel-vfs"
            | "kernel-block-io"
            | "full-kernel-no-daemon"
            | "multi-process-distributed"
    )
}

fn is_safe_ci_artifact_ref(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && trimmed.len() <= 128
        && !trimmed.starts_with('.')
        && !trimmed.contains("..")
        && !trimmed.contains("ghp_")
        && !trimmed.contains("github_pat")
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn is_safe_ci_run_url(value: &str) -> bool {
    const PREFIX: &str = "https://github.com/tidefs/tidefs/actions/runs/";
    value
        .strip_prefix(PREFIX)
        .filter(|run_id| !run_id.is_empty())
        .is_some_and(|run_id| run_id.chars().all(|ch| ch.is_ascii_digit()))
}

fn digest_backend_steps<'a>(
    events: impl IntoIterator<Item = &'a BackendStep>,
) -> Result<String, TraceError> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for event in events {
        hasher.update(serde_json::to_vec(event)?);
        hasher.update(b"\n");
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn final_backend_fingerprint(events: &[BackendStep]) -> String {
    events
        .iter()
        .rev()
        .find_map(|event| event.fingerprint.as_deref())
        .unwrap_or("")
        .to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn format_unix_seconds_utc(seconds: i64) -> String {
    const SECONDS_PER_DAY: i64 = 86_400;

    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let seconds_of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::backend::{
        BackendCompletion, FingerprintDelta, TraceComparison, TraceMismatch, BACKEND_LOCAL_RUNTIME,
        BACKEND_MODEL,
    };
    use crate::save_trace;

    fn trace_operation(op: &str) -> TraceOperation {
        TraceOperation {
            op: op.into(),
            args: json!({}),
            expect: json!({}),
        }
    }

    fn backend_step(
        backend: &str,
        operation_index: usize,
        fingerprint: Option<&str>,
    ) -> BackendStep {
        BackendStep {
            backend: backend.into(),
            operation_index,
            operation: trace_operation(if operation_index == 0 {
                OP_TRACE_META
            } else {
                "create_pool"
            }),
            completion: BackendCompletion {
                status: "success".into(),
                disposition: "final".into(),
                errno: "SUCCESS".into(),
                completed_bytes: 0,
                result: None,
                error: None,
            },
            fingerprint: fingerprint.map(str::to_string),
        }
    }

    fn write_minimal_trace(dir: &TempDir, file_name: &str) -> PathBuf {
        let path = dir.path().join(file_name);
        save_trace(
            &path,
            &[
                json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
                json!({"op": "create_pool", "args": {"device_count": 1, "device_size_bytes": 4194304}}),
            ],
        )
        .unwrap();
        path
    }

    fn runtime_metadata() -> RuntimeTraceArtifactMetadata {
        RuntimeTraceArtifactMetadata {
            runtime_backend: RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE.into(),
            validation_tier: "mounted-userspace".into(),
            ci_artifact_ref: "trace-compare-smoke-churn-42".into(),
            ci_run_url: "https://github.com/tidefs/tidefs/actions/runs/1234567890".into(),
            claims_covered: vec!["trace.runtime.compare.v1".into()],
            notes: String::new(),
        }
    }

    fn runtime_comparison(trace_path: PathBuf, runtime_backend: &str) -> TraceComparison {
        TraceComparison {
            trace_path,
            model_events: vec![
                backend_step(BACKEND_MODEL, 0, None),
                backend_step(BACKEND_MODEL, 1, Some("model-final")),
            ],
            runtime_events: vec![
                backend_step(runtime_backend, 0, None),
                backend_step(runtime_backend, 1, Some("runtime-final")),
            ],
            mismatches: Vec::new(),
        }
    }

    #[test]
    fn model_replay_manifest_populates_required_v1_fields() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "model.jsonl");
        let events = vec![
            backend_step(BACKEND_MODEL, 0, None),
            backend_step(
                BACKEND_MODEL,
                1,
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
        ];

        let manifest = TraceArtifactManifest::model_replay(
            &trace_path,
            "traces/golden/model.jsonl",
            "model_trace",
            &events,
            ArtifactRunResult::Pass,
            "2026-06-21T00:00:00Z",
        )
        .unwrap();

        assert_eq!(manifest.artifact_schema_version, 1);
        assert_eq!(manifest.trace_schema, "pool_trace_v1");
        assert_eq!(manifest.trace_version, 1);
        assert_eq!(manifest.request_contract_version, 1);
        assert_eq!(manifest.backend, "model");
        assert_eq!(manifest.validation_tier, "source-model");
        assert_eq!(manifest.evidence_class, "model-only");
        assert_eq!(manifest.input.trace_op_count, 2);
        assert_eq!(manifest.input.trace_descriptor, "model_trace");
        assert_eq!(manifest.output.result, "pass");
        assert_eq!(manifest.output.event_count, 2);
        assert_eq!(
            manifest.output.final_fingerprint,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(manifest.output.mismatches, 0);
        assert_eq!(manifest.output.events_digest_sha256.len(), 64);
        assert!(manifest.claims_covered.is_empty());
        assert!(manifest.ci_artifact_ref.is_none());
        assert!(manifest
            .notes
            .contains("Insufficient for runtime crash claims"));
    }

    #[test]
    fn local_comparison_manifest_is_harness_only_and_records_failure() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "compare.jsonl");
        let model_step = backend_step(BACKEND_MODEL, 1, Some("model-final"));
        let runtime_step = backend_step(BACKEND_LOCAL_RUNTIME, 1, Some("runtime-final"));
        let mismatch = TraceMismatch {
            operation_index: 1,
            request: trace_operation("create_pool"),
            model_completion: model_step.completion.clone(),
            runtime_completion: BackendCompletion {
                status: "failed".into(),
                disposition: "final".into(),
                errno: "EIO".into(),
                completed_bytes: 0,
                result: None,
                error: Some("boom".into()),
            },
            fingerprint_delta: FingerprintDelta {
                model: Some("model-final".into()),
                runtime: Some("runtime-final".into()),
            },
            replay_command: "cargo run -p tidefs-xtask -- check-trace-oracle --compare-trace trace"
                .into(),
        };
        let comparison = TraceComparison {
            trace_path,
            model_events: vec![backend_step(BACKEND_MODEL, 0, None), model_step],
            runtime_events: vec![backend_step(BACKEND_LOCAL_RUNTIME, 0, None), runtime_step],
            mismatches: vec![mismatch],
        };

        let manifest = TraceArtifactManifest::local_comparison(
            &comparison,
            "traces/compare.jsonl",
            "compare_trace",
            "2026-06-21T00:00:00Z",
        )
        .unwrap();

        assert_eq!(manifest.backend, "compare");
        assert_eq!(manifest.validation_tier, "harness-only");
        assert_eq!(manifest.evidence_class, "harness-only");
        assert_eq!(manifest.output.result, "fail");
        assert_eq!(manifest.output.mismatches, 1);
        assert_eq!(manifest.output.event_count, 4);
        assert_eq!(manifest.output.final_fingerprint, "runtime-final");
        assert_eq!(manifest.output.events_digest_sha256.len(), 64);
        assert!(manifest.notes.contains("not mounted runtime"));
    }

    #[test]
    fn runtime_comparison_manifest_requires_mounted_backend_and_ci_refs() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "runtime.jsonl");
        let comparison = runtime_comparison(trace_path, RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE);

        let manifest = TraceArtifactManifest::runtime_comparison(
            &comparison,
            "traces/runtime.jsonl",
            "runtime_trace",
            runtime_metadata(),
            "2026-06-21T00:00:00Z",
        )
        .unwrap();

        assert_eq!(manifest.backend, "compare");
        assert_eq!(manifest.validation_tier, "mounted-userspace");
        assert_eq!(manifest.evidence_class, "runtime");
        assert_eq!(
            manifest.ci_artifact_ref.as_deref(),
            Some("trace-compare-smoke-churn-42")
        );
        assert_eq!(
            manifest.ci_run_url.as_deref(),
            Some("https://github.com/tidefs/tidefs/actions/runs/1234567890")
        );
        assert_eq!(
            manifest.claims_covered,
            vec!["trace.runtime.compare.v1".to_string()]
        );
        assert_eq!(manifest.output.result, "pass");
        assert_eq!(manifest.output.final_fingerprint, "runtime-final");
        assert!(manifest.notes.contains("mounted/runtime backend"));
    }

    #[test]
    fn local_runtime_comparison_cannot_be_upgraded_to_runtime() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "local.jsonl");
        let comparison = runtime_comparison(trace_path, BACKEND_LOCAL_RUNTIME);

        let err = TraceArtifactManifest::runtime_comparison(
            &comparison,
            "traces/local.jsonl",
            "local_trace",
            runtime_metadata(),
            "2026-06-21T00:00:00Z",
        )
        .expect_err("local runtime harness must not become runtime evidence");

        assert!(err
            .to_string()
            .contains("requires all runtime events to use mounted/runtime backend"));
    }

    #[test]
    fn runtime_manifest_rejects_missing_runtime_metadata() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "bad-metadata.jsonl");
        let comparison = runtime_comparison(trace_path, RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE);
        let mut metadata = runtime_metadata();
        metadata.ci_artifact_ref = "/tmp/runner/trace-output".into();

        let err = TraceArtifactManifest::runtime_comparison(
            &comparison,
            "traces/bad-metadata.jsonl",
            "bad_metadata",
            metadata,
            "2026-06-21T00:00:00Z",
        )
        .expect_err("runner-local artifact paths must fail closed");

        assert!(err
            .to_string()
            .contains("safe GitHub Actions artifact name"));
    }

    #[test]
    fn runtime_manifest_rejects_runner_local_run_url() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "bad-url.jsonl");
        let comparison = runtime_comparison(trace_path, RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE);
        let mut metadata = runtime_metadata();
        metadata.ci_run_url = "https://ci1.internal/actions/runs/123".into();

        let err = TraceArtifactManifest::runtime_comparison(
            &comparison,
            "traces/bad-url.jsonl",
            "bad_url",
            metadata,
            "2026-06-21T00:00:00Z",
        )
        .expect_err("runner-local run URLs must fail closed");

        assert!(err
            .to_string()
            .contains("tidefs/tidefs GitHub Actions run URL"));
    }

    #[test]
    fn runtime_manifest_rejects_non_runtime_validation_tier() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "bad-tier.jsonl");
        let comparison = runtime_comparison(trace_path, RUNTIME_TRACE_BACKEND_MOUNTED_USERSPACE);
        let mut metadata = runtime_metadata();
        metadata.validation_tier = "harness-only".into();

        let err = TraceArtifactManifest::runtime_comparison(
            &comparison,
            "traces/bad-tier.jsonl",
            "bad_tier",
            metadata,
            "2026-06-21T00:00:00Z",
        )
        .expect_err("harness-only tier must not become runtime evidence");

        assert!(err.to_string().contains("not a runtime tier"));
    }

    #[test]
    fn malformed_trace_metadata_fails_closed() {
        let temp = TempDir::new().unwrap();
        let trace_path = temp.path().join("malformed.jsonl");
        save_trace(
            &trace_path,
            &[
                json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1"}}),
                json!({"op": "create_pool", "args": {}}),
            ],
        )
        .unwrap();
        let err = describe_trace_input(&trace_path, "malformed.jsonl", "malformed".into())
            .expect_err("missing version must fail closed");
        assert!(err
            .to_string()
            .contains("trace_meta missing numeric version"));
    }

    #[test]
    fn artifact_ids_are_sanitized() {
        assert_eq!(
            sanitize_artifact_id("traces/golden/smoke churn/pool_trace.jsonl"),
            "traces-golden-smoke-churn-pool_trace.jsonl"
        );
    }

    #[test]
    fn generated_at_utc_formats_unix_epoch() {
        assert_eq!(format_unix_seconds_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn manifest_json_uses_schema_field_names() {
        let temp = TempDir::new().unwrap();
        let trace_path = write_minimal_trace(&temp, "json.jsonl");
        let events = vec![backend_step(BACKEND_MODEL, 0, None)];
        let manifest = TraceArtifactManifest::model_replay(
            &trace_path,
            "json.jsonl",
            "json",
            &events,
            ArtifactRunResult::Skipped,
            "2026-06-21T00:00:00Z",
        )
        .unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        let object = value.as_object().unwrap();
        for field in [
            "artifact_schema_version",
            "trace_schema",
            "trace_version",
            "request_contract_version",
            "backend",
            "environment_model",
            "validation_tier",
            "evidence_class",
            "generated_at",
            "generated_by",
            "input",
            "output",
            "claims_covered",
            "ci_artifact_ref",
            "ci_run_url",
            "notes",
        ] {
            assert!(object.contains_key(field), "missing field {field}");
        }
        let mut expected = BTreeMap::new();
        expected.insert("result", "skipped");
        assert_eq!(
            value["output"]["result"].as_str(),
            expected.get("result").copied()
        );
    }
}
