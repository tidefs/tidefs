#![forbid(unsafe_code)]

//! Local runtime crash report schema and verifier.
//!
//! This module defines [`RuntimeCrashReport`], a report type that is distinct
//! from the model-only [`crate::CrashOracleReport`].  A runtime report records
//! the result of injecting a crash point into a live TideFS mount and
//! recovering.  The verifier checks that required metadata fields are present,
//! but does **not** validate the runtime crash claim itself: a passing schema
//! verifier is necessary but not sufficient for establishing runtime crash
//! safety.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{CrashClassification, CrashInjectionPoint, CrashOracleError};

pub const RUNTIME_REPORT_VERSION: u64 = 1;

/// Classification of a runtime crash outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCrashOutcome {
    /// Filesystem recovered to a consistent state.
    Recovered,
    /// Data written before the crash point was lost (unsynced).
    LostUnfsynced,
    /// Recovery produced corruption or inconsistency.
    Corrupted,
    /// Mount failed entirely after the crash.
    MountFailed,
    /// Kernel or device panicked and could not be observed.
    KernelPanic,
}

impl fmt::Display for RuntimeCrashOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovered => write!(f, "recovered"),
            Self::LostUnfsynced => write!(f, "lost-unfsynced"),
            Self::Corrupted => write!(f, "corrupted"),
            Self::MountFailed => write!(f, "mount-failed"),
            Self::KernelPanic => write!(f, "kernel-panic"),
        }
    }
}

/// A local runtime crash report produced by injecting a crash point into a
/// live TideFS mount and recording the recovery result.
///
/// This type is intentionally distinct from [`crate::CrashOracleReport`], which
/// records model-only crash matrices derived from the pure state machine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeCrashReport {
    /// Schema version for this report format.
    pub report_version: u64,

    /// Identity of the runtime backend that produced this report
    /// (e.g. `"tidefs-fuse-local"`, `"tidefs-ublk-local"`).
    pub runtime_backend: String,

    /// The local runtime crash injection point that was exercised.
    pub injected_point: CrashInjectionPoint,

    /// Model-level crash classification derived from the observed outcome.
    pub classification: CrashClassification,

    /// Runtime outcome observed (corrupted, mount-failed, kernel-panic, etc.).
    pub outcome: RuntimeCrashOutcome,

    /// Recovered filesystem fingerprint after crash + recovery, as a hex
    /// string.  `None` when the mount failed or the fingerprint could not be
    /// obtained (e.g. kernel panic).
    pub recovered_fingerprint: Option<String>,

    /// Validation tier under which this test was executed
    /// (e.g. `"local-fuse"`, `"local-ublk"`, `"distributed"`).
    pub validation_tier: String,

    /// Filesystem path to the runtime artifact that produced this report.
    pub artifact_path: String,

    /// SHA-256 hex digest (or equivalent) of the artifact at `artifact_path`.
    pub artifact_digest: String,

    /// Mount path used during the test.
    pub mount_path: Option<String>,

    /// Claim ids that this runtime report provides evidence for
    /// (e.g. `"local.vfs.write_fsync_crash.v1"`).
    pub claim_ids: Vec<String>,

    /// Identifier for the tool or harness that generated this report.
    pub generated_by: String,
}

/// Discriminant embedded in JSON reports so the verifier can distinguish
/// runtime reports from model-only reports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportClass {
    Model,
    Runtime,
}

impl fmt::Display for ReportClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model => write!(f, "model"),
            Self::Runtime => write!(f, "runtime"),
        }
    }
}

/// Errors returned by the runtime report verifier.
#[derive(Debug)]
pub enum RuntimeReportError {
    /// A required field is missing or empty.
    MissingField(&'static str),
    /// The report JSON could not be parsed.
    InvalidJson(String),
    /// The report is a model-only report, but runtime evidence was required.
    ModelOnlyReport,
    /// The recovered fingerprint is missing when the outcome indicates a
    /// successful recovery.
    FingerprintMissingForOutcome,
    /// Schema version mismatch.
    UnsupportedVersion(u64),
    /// No claim ids present.
    NoClaimIds,
    /// A claim id that names a model-only scope cannot be supported by a
    /// runtime report.
    ClaimScopeMismatch(String),
}

impl fmt::Display for RuntimeReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidJson(err) => write!(f, "invalid report JSON: {err}"),
            Self::ModelOnlyReport => {
                write!(f, "report is model-only; runtime evidence report required")
            }
            Self::FingerprintMissingForOutcome => {
                write!(
                    f,
                    "recovered_fingerprint is required when outcome is Recovered or LostUnfsynced"
                )
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported runtime report version {v}")
            }
            Self::NoClaimIds => write!(f, "at least one claim id is required"),
            Self::ClaimScopeMismatch(id) => {
                write!(
                    f,
                    "claim id '{id}' names a model-only scope; runtime evidence required"
                )
            }
        }
    }
}

impl From<RuntimeReportError> for CrashOracleError {
    fn from(e: RuntimeReportError) -> Self {
        CrashOracleError::Report(e.to_string())
    }
}

/// Claim id prefixes that signal a model-only scope, which cannot be satisfied
/// by a runtime crash report.
const MODEL_ONLY_CLAIM_PREFIXES: &[&str] = &["model."];

/// Verify that a [`RuntimeCrashReport`] satisfies the runtime report schema.
///
/// # Checks
///
/// - All required identity/outcome fields are present and non-empty.
/// - The `claim_ids` list is non-empty and contains no model-only claim ids.
/// - The `recovered_fingerprint` is present when the outcome implies recovery
///   was attempted.
/// - The report version is supported.
///
/// # Scope
///
/// This verifier checks **metadata shape only**.  A passing verifier does not
/// imply that the runtime crash claim is valid; it only confirms the report
/// carries the required fields for downstream claim evaluation.
pub fn verify_runtime_crash_report(report: &RuntimeCrashReport) -> Result<(), RuntimeReportError> {
    // Version gate.
    if report.report_version != RUNTIME_REPORT_VERSION {
        return Err(RuntimeReportError::UnsupportedVersion(
            report.report_version,
        ));
    }

    // Required identity fields.
    check_non_empty(&report.runtime_backend, "runtime_backend")?;
    check_non_empty(&report.validation_tier, "validation_tier")?;
    check_non_empty(&report.artifact_path, "artifact_path")?;
    check_non_empty(&report.artifact_digest, "artifact_digest")?;
    check_non_empty(&report.generated_by, "generated_by")?;
    match report.mount_path.as_deref() {
        Some(mount_path) => check_non_empty(mount_path, "mount_path")?,
        None => return Err(RuntimeReportError::MissingField("mount_path")),
    }

    // CrashInjectionPoint is a closed enum, so serde rejects missing or
    // unknown injected_point values before this verifier runs.

    // Claim ids.
    if report.claim_ids.is_empty() {
        return Err(RuntimeReportError::NoClaimIds);
    }

    for claim_id in &report.claim_ids {
        check_non_empty(claim_id, "claim_ids[]")?;
        if MODEL_ONLY_CLAIM_PREFIXES
            .iter()
            .any(|prefix| claim_id.starts_with(prefix))
        {
            return Err(RuntimeReportError::ClaimScopeMismatch(claim_id.clone()));
        }
    }

    // Fingerprint requirement: if the outcome indicates we attempted recovery,
    // the fingerprint must be present.
    match report.outcome {
        RuntimeCrashOutcome::Recovered | RuntimeCrashOutcome::LostUnfsynced => {
            match report.recovered_fingerprint.as_deref() {
                Some(fingerprint) if !fingerprint.trim().is_empty() => {}
                _ => return Err(RuntimeReportError::FingerprintMissingForOutcome),
            }
        }
        RuntimeCrashOutcome::Corrupted
        | RuntimeCrashOutcome::MountFailed
        | RuntimeCrashOutcome::KernelPanic => {
            // Fingerprint may or may not be available; no requirement.
        }
    }

    Ok(())
}

/// Classify a JSON report blob as model-only or runtime based on its embedded
/// discriminant.  Returns `Ok(ReportClass)` on success, or an error if the
/// report cannot be parsed.
///
/// This is the entry point for scope-confusion rejection: when a runtime
/// evidence verifier receives a model-only report, it must reject it.
pub fn classify_report(json: &str) -> Result<ReportClass, RuntimeReportError> {
    #[derive(Deserialize)]
    struct ReportEnvelope {
        report_class: Option<ReportClass>,
        evidence_scope: Option<String>,
    }

    let envelope: ReportEnvelope =
        serde_json::from_str(json).map_err(|e| RuntimeReportError::InvalidJson(e.to_string()))?;

    match envelope.report_class {
        Some(ReportClass::Runtime) => Ok(ReportClass::Runtime),
        Some(ReportClass::Model) => Ok(ReportClass::Model),
        None => {
            // Fallback: if the report carries an evidence_scope starting with
            // "model.", treat it as model-only.
            if envelope
                .evidence_scope
                .as_deref()
                .map_or(false, |s| s.starts_with("model."))
            {
                return Ok(ReportClass::Model);
            }
            // Unknown: return model to be safe (reject when runtime required).
            Ok(ReportClass::Model)
        }
    }
}

/// Verify that a JSON blob is a runtime report, not a model-only report, and
/// satisfies the runtime schema.  This combines scope classification and field
/// verification in one call for convenience.
pub fn verify_runtime_report_json(json: &str) -> Result<RuntimeCrashReport, RuntimeReportError> {
    let class = classify_report(json)?;
    if class != ReportClass::Runtime {
        return Err(RuntimeReportError::ModelOnlyReport);
    }

    let report: RuntimeCrashReport =
        serde_json::from_str(json).map_err(|e| RuntimeReportError::InvalidJson(e.to_string()))?;

    verify_runtime_crash_report(&report)?;
    Ok(report)
}

/// Serialize a [`RuntimeCrashReport`] to a JSON string.
pub fn serialize_runtime_report(report: &RuntimeCrashReport) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct RuntimeReportEnvelope<'a> {
        report_class: ReportClass,
        #[serde(flatten)]
        report: &'a RuntimeCrashReport,
    }

    serde_json::to_string_pretty(&RuntimeReportEnvelope {
        report_class: ReportClass::Runtime,
        report,
    })
}

/// Write a [`RuntimeCrashReport`] to a file.
pub fn write_runtime_report(
    report: &RuntimeCrashReport,
    path: &Path,
) -> Result<(), CrashOracleError> {
    let json = serialize_runtime_report(report)
        .map_err(|e| CrashOracleError::Report(format!("serialize runtime report: {e}")))?;
    std::fs::write(path, &json).map_err(|e| {
        CrashOracleError::Report(format!("write runtime report to {}: {e}", path.display()))
    })?;
    Ok(())
}

fn check_non_empty(value: &str, field: &'static str) -> Result<(), RuntimeReportError> {
    if value.trim().is_empty() {
        return Err(RuntimeReportError::MissingField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CrashInjectionPoint;

    fn valid_runtime_report() -> RuntimeCrashReport {
        RuntimeCrashReport {
            report_version: RUNTIME_REPORT_VERSION,
            runtime_backend: "tidefs-fuse-local".into(),
            injected_point: CrashInjectionPoint::AfterFsyncBeforeUnmount,
            classification: CrashClassification::Valid,
            outcome: RuntimeCrashOutcome::Recovered,
            recovered_fingerprint: Some("abcd1234".into()),
            validation_tier: "local-fuse".into(),
            artifact_path: "/tmp/crash-artifact.tar.gz".into(),
            artifact_digest: "sha256:deadbeef".into(),
            mount_path: Some("/mnt/tidefs".into()),
            claim_ids: vec!["local.vfs.write_fsync_crash.v1".into()],
            generated_by: "tidefs-crash-harness/0.1".into(),
        }
    }

    #[test]
    fn valid_report_passes_verification() {
        let report = valid_runtime_report();
        verify_runtime_crash_report(&report).expect("valid report should pass");
    }

    #[test]
    fn reject_missing_runtime_backend() {
        let mut report = valid_runtime_report();
        report.runtime_backend = String::new();
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(
            matches!(err, RuntimeReportError::MissingField("runtime_backend")),
            "expected MissingField, got {err}"
        );
    }

    #[test]
    fn reject_missing_validation_tier() {
        let mut report = valid_runtime_report();
        report.validation_tier = String::new();
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("validation_tier")
        ));
    }

    #[test]
    fn reject_missing_artifact_path() {
        let mut report = valid_runtime_report();
        report.artifact_path = String::new();
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("artifact_path")
        ));
    }

    #[test]
    fn reject_missing_artifact_digest() {
        let mut report = valid_runtime_report();
        report.artifact_digest = String::new();
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("artifact_digest")
        ));
    }

    #[test]
    fn reject_missing_generated_by() {
        let mut report = valid_runtime_report();
        report.generated_by = String::new();
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("generated_by")
        ));
    }

    #[test]
    fn reject_missing_mount_path() {
        let mut report = valid_runtime_report();
        report.mount_path = None;
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("mount_path")
        ));
    }

    #[test]
    fn reject_blank_mount_path() {
        let mut report = valid_runtime_report();
        report.mount_path = Some(" ".into());
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("mount_path")
        ));
    }

    #[test]
    fn reject_empty_claim_ids() {
        let mut report = valid_runtime_report();
        report.claim_ids = vec![];
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(err, RuntimeReportError::NoClaimIds));
    }

    #[test]
    fn reject_blank_claim_id() {
        let mut report = valid_runtime_report();
        report.claim_ids = vec![" ".into()];
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::MissingField("claim_ids[]")
        ));
    }

    #[test]
    fn reject_model_only_claim_scope() {
        let mut report = valid_runtime_report();
        report.claim_ids = vec!["model.write_fsync_crash_matrix.v1".into()];
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(err, RuntimeReportError::ClaimScopeMismatch(_)));
    }

    #[test]
    fn reject_unsupported_version() {
        let mut report = valid_runtime_report();
        report.report_version = 99;
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(err, RuntimeReportError::UnsupportedVersion(99)));
    }

    #[test]
    fn fingerprint_required_when_recovered() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::Recovered;
        report.recovered_fingerprint = None;
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::FingerprintMissingForOutcome
        ));
    }

    #[test]
    fn blank_fingerprint_rejected_when_recovered() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::Recovered;
        report.recovered_fingerprint = Some(" ".into());
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::FingerprintMissingForOutcome
        ));
    }

    #[test]
    fn fingerprint_required_when_lost_unfsynced() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::LostUnfsynced;
        report.recovered_fingerprint = None;
        let err = verify_runtime_crash_report(&report).unwrap_err();
        assert!(matches!(
            err,
            RuntimeReportError::FingerprintMissingForOutcome
        ));
    }

    #[test]
    fn fingerprint_optional_when_mount_failed() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::MountFailed;
        report.recovered_fingerprint = None;
        verify_runtime_crash_report(&report).expect("mount-failed without fingerprint ok");
    }

    #[test]
    fn fingerprint_optional_when_kernel_panic() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::KernelPanic;
        report.recovered_fingerprint = None;
        verify_runtime_crash_report(&report).expect("kernel-panic without fingerprint ok");
    }

    #[test]
    fn fingerprint_optional_when_corrupted() {
        let mut report = valid_runtime_report();
        report.outcome = RuntimeCrashOutcome::Corrupted;
        report.recovered_fingerprint = None;
        verify_runtime_crash_report(&report).expect("corrupted without fingerprint ok");
    }

    #[test]
    fn model_report_rejected_by_runtime_json_verifier() {
        // Build a minimal model-report JSON and verify the runtime verifier
        // rejects it as model-only.
        let model_json = serde_json::json!({
            "report_class": "model",
            "report_version": 1,
            "generated_by": "tidefs-crash-oracle",
            "evidence_scope": "model.write_fsync_crash_matrix.v1",
            "runtime_claim_boundary": "fail-closed",
            "matrices": [],
            "runtime_claims": []
        })
        .to_string();

        let result = verify_runtime_report_json(&model_json);
        assert!(
            matches!(result, Err(RuntimeReportError::ModelOnlyReport)),
            "expected ModelOnlyReport, got {result:?}"
        );
    }

    #[test]
    fn model_evidence_scope_triggers_model_classification() {
        let json = serde_json::json!({
            "report_version": 1,
            "evidence_scope": "model.write_fsync_crash_matrix.v1"
        })
        .to_string();

        let class = classify_report(&json).expect("classify");
        assert_eq!(class, ReportClass::Model);
    }

    #[test]
    fn runtime_report_class_enables_runtime_verification() {
        let report = valid_runtime_report();
        let json = serialize_runtime_report(&report).expect("serialize");

        let class = classify_report(&json).expect("classify");
        assert_eq!(class, ReportClass::Runtime);

        let verified = verify_runtime_report_json(&json).expect("verify serialized report");
        assert_eq!(verified.runtime_backend, "tidefs-fuse-local");
    }

    #[test]
    fn runtime_report_json_round_trips() {
        let report = valid_runtime_report();
        let json = serialize_runtime_report(&report).expect("serialize");
        let decoded: RuntimeCrashReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, report);
    }

    #[test]
    fn missing_injected_point_is_rejected_by_json_verifier() {
        let report = valid_runtime_report();
        let json = serialize_runtime_report(&report).expect("serialize");
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        value
            .as_object_mut()
            .expect("runtime report envelope")
            .remove("injected_point");

        let err = verify_runtime_report_json(&value.to_string()).unwrap_err();
        assert!(
            matches!(err, RuntimeReportError::InvalidJson(message) if message.contains("injected_point")),
            "expected injected_point parse error, got {err}"
        );
    }

    #[test]
    fn invalid_json_is_rejected_without_leaking_parse_errors() {
        let err = classify_report("{not-json").unwrap_err();
        assert!(matches!(err, RuntimeReportError::InvalidJson(_)));
    }

    #[test]
    fn all_runtime_outcomes_round_trip() {
        for outcome in &[
            RuntimeCrashOutcome::Recovered,
            RuntimeCrashOutcome::LostUnfsynced,
            RuntimeCrashOutcome::Corrupted,
            RuntimeCrashOutcome::MountFailed,
            RuntimeCrashOutcome::KernelPanic,
        ] {
            let json = serde_json::to_string(outcome).expect("serialize outcome");
            let decoded: RuntimeCrashOutcome =
                serde_json::from_str(&json).expect("deserialize outcome");
            assert_eq!(*outcome, decoded);
        }
    }
}
