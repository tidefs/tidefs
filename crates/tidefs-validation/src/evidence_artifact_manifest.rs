// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reusable claim evidence artifact manifests.
//!
//! Claim-producing tools write these records next to the artifact they
//! generate so claim receipts can cite evidence without learning each
//! artifact's private JSON or TOML shape.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;

pub const EVIDENCE_ARTIFACT_MANIFEST_VERSION: u32 = 2;
pub const EVIDENCE_ARTIFACT_DIGEST_ALGORITHM: &str = "blake3";
pub const MISSING_EVIDENCE_CONTENT_DIGEST: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

const BLOCKED_PASS_DIGEST_INPUTS: &[&[u8]] = &[
    &[
        115, 117, 109, 109, 97, 114, 121, 45, 110, 111, 116, 45, 97, 118, 97, 105, 108, 97, 98,
        108, 101,
    ],
    &[112, 108, 97, 99, 101, 104, 111, 108, 100, 101, 114],
    &[102, 97, 107, 101],
    &[100, 117, 109, 109, 121],
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactManifest {
    pub manifest_version: u32,
    pub claim_id: String,
    pub evidence_class: String,
    pub validation_tier: ValidationTier,
    pub scope: String,
    pub artifact_path: String,
    pub content_digest: String,
    pub run_id: String,
    pub source_ref: String,
    pub outcome: ValidationStatus,
    pub residual_risk: String,
    pub source: String,
    pub generated_at: String,
    pub blocking_issues: Vec<BlockingIssueRef>,
}

#[derive(Clone, Debug, Deserialize)]
struct EvidenceArtifactManifestVersionProbe {
    manifest_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockingIssueRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceArtifactManifestError {
    failures: Vec<String>,
}

impl EvidenceArtifactManifestError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    fn single(failure: impl Into<String>) -> Self {
        Self {
            failures: vec![failure.into()],
        }
    }

    fn from_failures(failures: Vec<String>) -> Result<(), Self> {
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Self { failures })
        }
    }
}

impl fmt::Display for EvidenceArtifactManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "evidence artifact manifest validation failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for EvidenceArtifactManifestError {}

impl EvidenceArtifactManifest {
    pub fn validate(&self) -> Result<(), EvidenceArtifactManifestError> {
        let mut failures = Vec::new();

        if self.manifest_version != EVIDENCE_ARTIFACT_MANIFEST_VERSION {
            failures.push(format!(
                "manifest_version must be {EVIDENCE_ARTIFACT_MANIFEST_VERSION}, found {}",
                self.manifest_version
            ));
        }
        if self.claim_id.trim().is_empty() {
            failures.push("claim_id must not be empty".to_string());
        }
        if self.evidence_class.trim().is_empty() {
            failures.push("evidence_class must not be empty".to_string());
        }
        if self.scope.trim().is_empty() {
            failures.push("scope must not be empty".to_string());
        }
        if let Err(error) = validate_artifact_path_shape(&self.artifact_path) {
            failures.extend(error.failures().iter().cloned());
        }
        if is_runtime_artifact_path(Path::new(&self.artifact_path))
            && !self.validation_tier.is_live_runtime()
        {
            failures
                .push("runtime artifact_path requires live-runtime validation_tier".to_string());
        }
        if self.validation_tier.is_live_runtime()
            && !is_runtime_artifact_path(Path::new(&self.artifact_path))
        {
            failures
                .push("live-runtime validation_tier requires runtime artifact_path".to_string());
        }
        validate_content_digest(&self.content_digest, &mut failures);
        validate_required_text("run_id", &self.run_id, &mut failures);
        validate_required_text("source_ref", &self.source_ref, &mut failures);
        validate_required_text("residual_risk", &self.residual_risk, &mut failures);
        validate_required_text("source", &self.source, &mut failures);
        validate_generated_at(&self.generated_at, &mut failures);
        validate_outcome_tier_combination(
            self.outcome,
            self.validation_tier,
            &self.content_digest,
            &self.blocking_issues,
            &mut failures,
        );

        for issue in &self.blocking_issues {
            if issue.number == 0 {
                failures.push("blocking_issues.number must be nonzero".to_string());
            }
            if let Some(repo) = &issue.repo {
                if repo.trim().is_empty() {
                    failures.push("blocking_issues.repo must not be empty".to_string());
                }
            }
            if let Some(reason) = &issue.reason {
                if reason.trim().is_empty() {
                    failures.push("blocking_issues.reason must not be empty".to_string());
                }
            }
        }

        EvidenceArtifactManifestError::from_failures(failures)
    }

    pub fn artifact_path_under(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<PathBuf, EvidenceArtifactManifestError> {
        validate_artifact_path_shape(&self.artifact_path)?;
        let root = root.as_ref();
        let canonical_root = root.canonicalize().map_err(|error| {
            EvidenceArtifactManifestError::single(format!(
                "resolve artifact root `{}`: {error}",
                root.display()
            ))
        })?;
        let artifact_path = canonical_root.join(&self.artifact_path);
        let canonical_artifact_path = artifact_path.canonicalize().map_err(|error| {
            EvidenceArtifactManifestError::single(format!(
                "read artifact_path `{}` under `{}`: {error}",
                self.artifact_path,
                canonical_root.display()
            ))
        })?;
        if !canonical_artifact_path.starts_with(&canonical_root) {
            return Err(EvidenceArtifactManifestError::single(format!(
                "artifact_path `{}` resolves outside artifact root `{}`",
                self.artifact_path,
                canonical_root.display()
            )));
        }
        Ok(canonical_artifact_path)
    }

    pub fn verify_artifact_digest(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<(), EvidenceArtifactManifestError> {
        self.validate()?;
        let artifact_path = self.artifact_path_under(root)?;
        let artifact = fs::read(&artifact_path).map_err(|error| {
            EvidenceArtifactManifestError::single(format!(
                "read artifact_path `{}`: {error}",
                artifact_path.display()
            ))
        })?;
        let actual = content_digest_for_bytes(&artifact);
        if actual != canonical_content_digest(&self.content_digest) {
            return Err(EvidenceArtifactManifestError::single(format!(
                "content_digest mismatch for `{}`: manifest `{}`, actual `{actual}`",
                self.artifact_path, self.content_digest
            )));
        }
        Ok(())
    }

    pub fn to_json_pretty(&self) -> Result<String, EvidenceArtifactManifestError> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|error| {
            EvidenceArtifactManifestError::single(format!("serialize manifest JSON: {error}"))
        })
    }
}

pub fn parse_evidence_artifact_manifest_json(
    text: &str,
) -> Result<EvidenceArtifactManifest, EvidenceArtifactManifestError> {
    let version = serde_json::from_str::<EvidenceArtifactManifestVersionProbe>(text)
        .map_err(|error| {
            EvidenceArtifactManifestError::single(format!(
                "manifest JSON does not include a supported manifest_version: {error}"
            ))
        })?
        .manifest_version;
    if version < EVIDENCE_ARTIFACT_MANIFEST_VERSION {
        return Err(EvidenceArtifactManifestError::single(format!(
            "manifest_version {version} is retired pre-standardization input; regenerate as manifest_version {EVIDENCE_ARTIFACT_MANIFEST_VERSION} with explicit run_id, source_ref, outcome, residual_risk, generated_at, and blocking_issues before using it for claim closure"
        )));
    }
    if version > EVIDENCE_ARTIFACT_MANIFEST_VERSION {
        return Err(EvidenceArtifactManifestError::single(format!(
            "manifest_version must be {EVIDENCE_ARTIFACT_MANIFEST_VERSION}, found {version}"
        )));
    }

    let manifest = serde_json::from_str::<EvidenceArtifactManifest>(text).map_err(|error| {
        EvidenceArtifactManifestError::single(format!(
            "manifest JSON does not match schema: {error}"
        ))
    })?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn load_evidence_artifact_manifest_json_path(
    path: impl AsRef<Path>,
) -> Result<EvidenceArtifactManifest, EvidenceArtifactManifestError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| {
        EvidenceArtifactManifestError::single(format!("read `{}`: {error}", path.display()))
    })?;
    parse_evidence_artifact_manifest_json(&text)
}

#[must_use]
pub fn content_digest_for_bytes(bytes: &[u8]) -> String {
    format!(
        "{EVIDENCE_ARTIFACT_DIGEST_ALGORITHM}:{}",
        blake3::hash(bytes).to_hex()
    )
}

pub fn content_digest_for_path(
    path: impl AsRef<Path>,
) -> Result<String, EvidenceArtifactManifestError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| {
        EvidenceArtifactManifestError::single(format!("read `{}`: {error}", path.display()))
    })?;
    Ok(content_digest_for_bytes(&bytes))
}

pub fn validate_artifact_path_shape(path: &str) -> Result<(), EvidenceArtifactManifestError> {
    let mut failures = Vec::new();
    validate_relative_artifact_path(path, &mut failures);
    EvidenceArtifactManifestError::from_failures(failures)
}

#[must_use]
pub fn is_runtime_artifact_path(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if file_name.to_ascii_lowercase().ends_with(".manifest.json") {
        return false;
    }

    path.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|component| {
            component
                .split(|byte: char| !byte.is_ascii_alphanumeric())
                .any(|token| token.eq_ignore_ascii_case("runtime"))
        })
    })
}

fn validate_relative_artifact_path(path: &str, failures: &mut Vec<String>) {
    if path.trim().is_empty() {
        failures.push("artifact_path must not be empty".to_string());
        return;
    }
    if path.contains("://") {
        failures.push("artifact_path must be workspace-relative, not a URL".to_string());
    }
    if path.starts_with('~') {
        failures.push("artifact_path must not use a home-directory shortcut".to_string());
    }
    if is_windows_absolute_path(path) {
        failures.push("artifact_path must be relative".to_string());
    }
    if path.contains('$') || path.contains('`') {
        failures.push(
            "artifact_path must not contain shell interpolation or secret expressions".to_string(),
        );
    }

    let path = Path::new(path);
    if path.is_absolute() {
        failures.push("artifact_path must be relative".to_string());
    }

    let mut has_normal = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_normal = true,
            Component::CurDir => {}
            Component::ParentDir => {
                failures.push("artifact_path must not contain `..`".to_string());
            }
            Component::RootDir | Component::Prefix(_) => {
                failures.push("artifact_path must be relative".to_string());
            }
        }
    }
    if !has_normal {
        failures.push("artifact_path must name a file".to_string());
    }
}

fn validate_required_text(field: &str, value: &str, failures: &mut Vec<String>) {
    if value.trim().is_empty() {
        failures.push(format!("{field} must not be empty"));
    }
    if value.contains("${{ secrets.") || value.contains("secrets.") {
        failures.push(format!("{field} must not contain runner secret references"));
    }
}

fn validate_generated_at(generated_at: &str, failures: &mut Vec<String>) {
    validate_required_text("generated_at", generated_at, failures);
    if !generated_at.trim().is_empty()
        && (!generated_at.contains('T')
            || !(generated_at.ends_with('Z') || generated_at.contains('+')))
    {
        failures.push(
            "generated_at must be a reviewable RFC3339-style timestamp such as 2026-06-22T13:00:00Z"
                .to_string(),
        );
    }
}

fn validate_outcome_tier_combination(
    outcome: ValidationStatus,
    validation_tier: ValidationTier,
    content_digest: &str,
    blocking_issues: &[BlockingIssueRef],
    failures: &mut Vec<String>,
) {
    if outcome == ValidationStatus::Pass && !blocking_issues.is_empty() {
        failures.push("outcome `pass` must not carry blocking_issues".to_string());
    }
    if outcome == ValidationStatus::Pass && is_unacceptable_pass_content_digest(content_digest) {
        failures.push("outcome `pass` requires a real artifact content_digest".to_string());
    }
    if outcome == ValidationStatus::EnvironmentRefusal
        && matches!(
            validation_tier,
            ValidationTier::SourceModel | ValidationTier::CargoUnit
        )
    {
        failures.push(format!(
            "outcome `environment-refusal` is invalid for validation_tier `{validation_tier}`"
        ));
    }
}

fn validate_content_digest(digest: &str, failures: &mut Vec<String>) {
    let Some(hex) = digest.strip_prefix(&format!("{EVIDENCE_ARTIFACT_DIGEST_ALGORITHM}:")) else {
        failures.push(format!(
            "content_digest must use `{EVIDENCE_ARTIFACT_DIGEST_ALGORITHM}:<64 hex>`"
        ));
        return;
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        failures.push(format!(
            "content_digest must use `{EVIDENCE_ARTIFACT_DIGEST_ALGORITHM}:<64 hex>`"
        ));
    }
}

fn is_unacceptable_pass_content_digest(digest: &str) -> bool {
    let canonical = canonical_content_digest(digest);
    canonical == MISSING_EVIDENCE_CONTENT_DIGEST
        || BLOCKED_PASS_DIGEST_INPUTS
            .iter()
            .any(|bytes| canonical == content_digest_for_bytes(bytes))
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn canonical_content_digest(digest: &str) -> String {
    digest.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> EvidenceArtifactManifest {
        EvidenceArtifactManifest {
            manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
            claim_id: "local.vfs.write_fsync_crash.v1".to_string(),
            evidence_class: "claims-gate-review".to_string(),
            validation_tier: ValidationTier::CargoUnit,
            scope: "claims-gate parser fixture".to_string(),
            artifact_path: "validation/artifacts/example/summary.json".to_string(),
            content_digest: content_digest_for_bytes(b"artifact bytes"),
            run_id: "123456789/1".to_string(),
            source_ref: "774b48046851ee844284b62a484573597c96a013".to_string(),
            outcome: ValidationStatus::Pass,
            residual_risk: "Fixture covers schema validation only; it is not runtime proof."
                .to_string(),
            source: "tidefs-validation-test".to_string(),
            generated_at: "2026-06-22T13:00:00Z".to_string(),
            blocking_issues: Vec::new(),
        }
    }

    #[test]
    fn version_two_manifest_round_trips_with_common_fields() {
        let manifest = valid_manifest();
        let json = manifest.to_json_pretty().expect("serialize manifest");
        assert!(json.contains("\"run_id\""));
        assert!(json.contains("\"source_ref\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"residual_risk\""));
        assert!(json.contains("\"blocking_issues\""));

        let parsed = parse_evidence_artifact_manifest_json(&json).expect("parse manifest");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn missing_common_field_fails_closed() {
        let mut value = serde_json::to_value(valid_manifest()).expect("manifest to json value");
        value
            .as_object_mut()
            .expect("manifest object")
            .remove("run_id");
        let err = parse_evidence_artifact_manifest_json(&value.to_string())
            .expect_err("missing run_id must fail");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("missing field `run_id`")));
    }

    #[test]
    fn version_one_manifest_is_retired_pre_standardization_input() {
        let json = r#"{
            "manifest_version": 1,
            "claim_id": "local.vfs.write_fsync_crash.v1",
            "evidence_class": "claims-gate-review",
            "validation_tier": "source-model",
            "source": "claims-gate",
            "scope": "old scope with hidden run data",
            "artifact_path": "validation/artifacts/crash-oracle/claims-gate-review.toml",
            "content_digest": "blake3:1111111111111111111111111111111111111111111111111111111111111111"
        }"#;

        let err = parse_evidence_artifact_manifest_json(json).expect_err("v1 manifests must fail");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("retired pre-standardization input")));
    }

    #[test]
    fn pass_outcome_cannot_carry_blocking_issues() {
        let mut manifest = valid_manifest();
        manifest.blocking_issues.push(BlockingIssueRef {
            repo: Some("tidefs/tidefs".to_string()),
            number: 809,
            reason: Some("fixture blocker".to_string()),
        });

        let err = manifest.validate().expect_err("pass with blockers fails");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("outcome `pass` must not carry blocking_issues")));
    }

    #[test]
    fn environment_refusal_is_invalid_for_source_model() {
        let mut manifest = valid_manifest();
        manifest.validation_tier = ValidationTier::SourceModel;
        manifest.outcome = ValidationStatus::EnvironmentRefusal;

        let err = manifest
            .validate()
            .expect_err("source-model environment refusal fails");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("environment-refusal")));
    }

    #[test]
    fn pass_outcome_rejects_missing_or_placeholder_digest() {
        for digest in [
            MISSING_EVIDENCE_CONTENT_DIGEST.to_string(),
            content_digest_for_bytes(b"summary-not-available"),
            content_digest_for_bytes(b"placeholder"),
            content_digest_for_bytes(b"fake"),
            content_digest_for_bytes(b"dummy"),
        ] {
            let mut manifest = valid_manifest();
            manifest.content_digest = digest;

            let err = manifest
                .validate()
                .expect_err("pass with missing or placeholder digest fails");
            assert!(err
                .failures()
                .iter()
                .any(|failure| failure.contains("real artifact content_digest")));
        }
    }

    #[test]
    fn artifact_path_rejects_host_urls_and_shell_interpolation() {
        for path in [
            "/tmp/summary.json",
            "https://github.com/tidefs/tidefs/actions/runs/1",
            "~/summary.json",
            "C:\\Users\\runner\\summary.json",
            "artifacts/$SECRET/summary.json",
        ] {
            let mut manifest = valid_manifest();
            manifest.artifact_path = path.to_string();
            let err = manifest.validate().expect_err("path must fail");
            assert!(
                err.failures()
                    .iter()
                    .any(|failure| failure.contains("artifact_path")),
                "missing artifact_path failure for {path}: {err:?}"
            );
        }
    }
}
