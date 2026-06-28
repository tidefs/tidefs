// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! v2 evidence artifact manifests for two-node harness evidence.
//!
//! The deterministic harness is an in-process loopback proof harness. Its
//! manifests are therefore limited to `harness-only` evidence unless a future
//! claim explicitly asks for that tier. QEMU carrier manifests require GitHub
//! Actions artifact metadata before they can use the `qemu-guest` runtime tier.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path};

pub const EVIDENCE_ARTIFACT_MANIFEST_VERSION: u32 = 2;
pub const EVIDENCE_ARTIFACT_DIGEST_ALGORITHM: &str = "blake3";
pub const TWO_NODE_SOURCE: &str = "tidefs-two-node-harness";
pub const TWO_NODE_DETERMINISTIC_EVIDENCE_CLASS: &str = "two-node-deterministic-harness";
pub const TWO_NODE_QEMU_TCP_EVIDENCE_CLASS: &str = "two-node-qemu-tcp-carrier-validation";
pub const TWO_NODE_DETERMINISTIC_NON_CLAIM_SCOPE: &str =
    "two-node.harness.deterministic-loopback.v1";
pub const TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE: &str = "two-node.qemu-tcp-carrier.v1";

const TWO_NODE_RISK_BOUNDARY: &str = "Two-node harness evidence does not validate multi-process distributed execution, RDMA, production cluster behavior, storage-node runtime behavior, release-candidate coverage, mounted runtime behavior, or OpenZFS/Ceph-class status.";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactManifest {
    pub manifest_version: u32,
    pub claim_id: String,
    pub evidence_class: String,
    pub validation_tier: EvidenceValidationTier,
    pub scope: String,
    pub artifact_path: String,
    pub content_digest: String,
    pub run_id: String,
    pub source_ref: String,
    pub outcome: EvidenceOutcome,
    pub residual_risk: String,
    pub source: String,
    pub generated_at: String,
    pub blocking_issues: Vec<BlockingIssueRef>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceValidationTier {
    HarnessOnly,
    QemuGuest,
    SourceModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOutcome {
    Pass,
    ProductFail,
    HarnessFail,
    EnvironmentRefusal,
    Skip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimBinding<'a> {
    ClaimId(&'a str),
    NonClaimScope(&'a str),
}

#[derive(Clone, Debug)]
pub struct DeterministicHarnessManifestInput<'a> {
    pub claim_binding: ClaimBinding<'a>,
    pub artifact_path: &'a str,
    pub artifact_bytes: &'a [u8],
    pub fixture_id: &'a str,
    pub source_ref: &'a str,
    pub generated_at: &'a str,
    pub outcome: EvidenceOutcome,
    pub blocking_issues: Vec<BlockingIssueRef>,
}

#[derive(Clone, Debug)]
pub struct QemuTcpCarrierManifestInput<'a> {
    pub claim_binding: ClaimBinding<'a>,
    pub artifact_path: &'a str,
    pub artifact_bytes: &'a [u8],
    pub github_actions: GitHubActionsArtifactRef<'a>,
    pub source_ref: &'a str,
    pub generated_at: &'a str,
    pub outcome: EvidenceOutcome,
    pub qemu_guest_detected: bool,
    pub blocking_issues: Vec<BlockingIssueRef>,
}

#[derive(Clone, Copy, Debug)]
pub struct GitHubActionsArtifactRef<'a> {
    pub workflow: &'a str,
    pub run_id: &'a str,
    pub run_attempt: &'a str,
    pub run_url: &'a str,
    pub artifact_name: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceManifestError {
    failures: Vec<String>,
}

impl EvidenceManifestError {
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

impl fmt::Display for EvidenceManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "two-node evidence manifest validation failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for EvidenceManifestError {}

impl EvidenceArtifactManifest {
    pub fn deterministic_harness(
        input: DeterministicHarnessManifestInput<'_>,
    ) -> Result<Self, EvidenceManifestError> {
        validate_deterministic_claim_binding(input.claim_binding)?;

        let manifest = Self {
            manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
            claim_id: claim_binding_id(input.claim_binding)?,
            evidence_class: TWO_NODE_DETERMINISTIC_EVIDENCE_CLASS.to_string(),
            validation_tier: EvidenceValidationTier::HarnessOnly,
            scope: format!(
                "deterministic in-process two-node loopback harness fixture `{}`; harness-only evidence; {TWO_NODE_RISK_BOUNDARY}",
                input.fixture_id
            ),
            artifact_path: input.artifact_path.to_string(),
            content_digest: content_digest_for_bytes(input.artifact_bytes),
            run_id: format!("deterministic-fixture:{}", input.fixture_id),
            source_ref: input.source_ref.to_string(),
            outcome: input.outcome,
            residual_risk: format!(
                "Deterministic loopback signal is harness-only and source/model-tier evidence at most. {TWO_NODE_RISK_BOUNDARY}"
            ),
            source: TWO_NODE_SOURCE.to_string(),
            generated_at: input.generated_at.to_string(),
            blocking_issues: input.blocking_issues,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn qemu_tcp_carrier(
        input: QemuTcpCarrierManifestInput<'_>,
    ) -> Result<Self, EvidenceManifestError> {
        if !input.qemu_guest_detected {
            return Err(EvidenceManifestError::single(
                "qemu-guest evidence requires qemu_guest_detected=true",
            ));
        }
        input.github_actions.validate()?;

        let manifest = Self {
            manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
            claim_id: claim_binding_id(input.claim_binding)?,
            evidence_class: TWO_NODE_QEMU_TCP_EVIDENCE_CLASS.to_string(),
            validation_tier: EvidenceValidationTier::QemuGuest,
            scope: format!(
                "QEMU guest live TCP carrier validation for two-node harness state transfer; github_actions_workflow={} github_actions_run={} artifact_name={}; not RDMA, not multi-process distributed storage-node runtime, and not release-candidate proof",
                input.github_actions.workflow,
                input.github_actions.run_url,
                input.github_actions.artifact_name
            ),
            artifact_path: input.artifact_path.to_string(),
            content_digest: content_digest_for_bytes(input.artifact_bytes),
            run_id: format!(
                "github-actions:{}:attempt:{}:artifact:{}",
                input.github_actions.run_id,
                input.github_actions.run_attempt,
                input.github_actions.artifact_name
            ),
            source_ref: input.source_ref.to_string(),
            outcome: input.outcome,
            residual_risk: format!(
                "QEMU TCP carrier evidence proves only the bounded live TCP carrier state-transfer row captured by the named GitHub Actions artifact. {TWO_NODE_RISK_BOUNDARY}"
            ),
            source: format!("{TWO_NODE_SOURCE}:qemu-tcp-carrier-validation"),
            generated_at: input.generated_at.to_string(),
            blocking_issues: input.blocking_issues,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), EvidenceManifestError> {
        let mut failures = Vec::new();
        if self.manifest_version != EVIDENCE_ARTIFACT_MANIFEST_VERSION {
            failures.push(format!(
                "manifest_version must be {EVIDENCE_ARTIFACT_MANIFEST_VERSION}, found {}",
                self.manifest_version
            ));
        }
        validate_required_text("claim_id", &self.claim_id, &mut failures);
        validate_required_text("evidence_class", &self.evidence_class, &mut failures);
        validate_required_text("scope", &self.scope, &mut failures);
        validate_relative_artifact_path(&self.artifact_path, &mut failures);
        validate_content_digest(&self.content_digest, &mut failures);
        validate_required_text("run_id", &self.run_id, &mut failures);
        validate_required_text("source_ref", &self.source_ref, &mut failures);
        validate_required_text("residual_risk", &self.residual_risk, &mut failures);
        validate_required_text("source", &self.source, &mut failures);
        validate_generated_at(&self.generated_at, &mut failures);
        validate_outcome_blockers(self.outcome, &self.blocking_issues, &mut failures);
        validate_two_node_boundary(self, &mut failures);

        for issue in &self.blocking_issues {
            if issue.number == 0 {
                failures.push("blocking_issues.number must be nonzero".to_string());
            }
            if let Some(repo) = &issue.repo {
                validate_required_text("blocking_issues.repo", repo, &mut failures);
            }
            if let Some(reason) = &issue.reason {
                validate_required_text("blocking_issues.reason", reason, &mut failures);
            }
        }

        EvidenceManifestError::from_failures(failures)
    }

    pub fn to_json_pretty(&self) -> Result<String, EvidenceManifestError> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|error| EvidenceManifestError::single(format!("serialize JSON: {error}")))
    }

    pub fn write_json_path(&self, path: impl AsRef<Path>) -> Result<(), EvidenceManifestError> {
        let json = self.to_json_pretty()?;
        fs::write(path.as_ref(), json).map_err(|error| {
            EvidenceManifestError::single(format!("write `{}`: {error}", path.as_ref().display()))
        })
    }
}

impl GitHubActionsArtifactRef<'_> {
    pub fn validate(&self) -> Result<(), EvidenceManifestError> {
        let mut failures = Vec::new();
        validate_required_text("github_actions.workflow", self.workflow, &mut failures);
        validate_required_text("github_actions.run_id", self.run_id, &mut failures);
        validate_required_text(
            "github_actions.run_attempt",
            self.run_attempt,
            &mut failures,
        );
        validate_required_text("github_actions.run_url", self.run_url, &mut failures);
        validate_required_text(
            "github_actions.artifact_name",
            self.artifact_name,
            &mut failures,
        );

        if !self.run_id.bytes().all(|b| b.is_ascii_digit()) {
            failures.push("github_actions.run_id must be a numeric GitHub Actions run id".into());
        }
        if !self.run_attempt.bytes().all(|b| b.is_ascii_digit()) {
            failures.push("github_actions.run_attempt must be numeric".into());
        }
        if !self
            .run_url
            .starts_with("https://github.com/tidefs/tidefs/actions/runs/")
        {
            failures.push("github_actions.run_url must be a tidefs/tidefs Actions run URL".into());
        }
        if self.artifact_name.contains('/') || self.artifact_name.contains('\\') {
            failures.push("github_actions.artifact_name must not contain path separators".into());
        }

        for (field, value) in [
            ("github_actions.workflow", self.workflow),
            ("github_actions.run_id", self.run_id),
            ("github_actions.run_attempt", self.run_attempt),
            ("github_actions.run_url", self.run_url),
            ("github_actions.artifact_name", self.artifact_name),
        ] {
            validate_no_runner_local_reference(field, value, &mut failures);
        }

        EvidenceManifestError::from_failures(failures)
    }
}

#[must_use]
pub fn content_digest_for_bytes(bytes: &[u8]) -> String {
    format!(
        "{EVIDENCE_ARTIFACT_DIGEST_ALGORITHM}:{}",
        blake3::hash(bytes).to_hex()
    )
}

fn claim_binding_id(binding: ClaimBinding<'_>) -> Result<String, EvidenceManifestError> {
    let mut failures = Vec::new();
    let id = match binding {
        ClaimBinding::ClaimId(claim_id) => {
            validate_required_text("claim_id", claim_id, &mut failures);
            claim_id.to_string()
        }
        ClaimBinding::NonClaimScope(scope) => {
            validate_required_text("non_claim_scope", scope, &mut failures);
            if scope.starts_with("non-claim:") {
                scope.to_string()
            } else {
                format!("non-claim:{scope}")
            }
        }
    };
    EvidenceManifestError::from_failures(failures)?;
    Ok(id)
}

fn validate_deterministic_claim_binding(
    binding: ClaimBinding<'_>,
) -> Result<(), EvidenceManifestError> {
    let ClaimBinding::ClaimId(claim_id) = binding else {
        return Ok(());
    };
    let normalized = claim_id.to_ascii_lowercase();
    for forbidden in [
        "multi-process",
        "distributed.runtime",
        "rdma",
        "production",
        "storage-node",
        "release-candidate",
    ] {
        if normalized.contains(forbidden) {
            return Err(EvidenceManifestError::single(format!(
                "deterministic harness evidence cannot bind runtime/product claim id `{claim_id}`"
            )));
        }
    }
    Ok(())
}

fn validate_two_node_boundary(manifest: &EvidenceArtifactManifest, failures: &mut Vec<String>) {
    if manifest.evidence_class == TWO_NODE_DETERMINISTIC_EVIDENCE_CLASS
        && manifest.validation_tier != EvidenceValidationTier::HarnessOnly
    {
        failures.push("deterministic two-node evidence must remain harness-only".into());
    }
    if manifest.evidence_class == TWO_NODE_QEMU_TCP_EVIDENCE_CLASS {
        if manifest.validation_tier != EvidenceValidationTier::QemuGuest {
            failures.push("QEMU TCP carrier evidence must use qemu-guest tier".into());
        }
        if !manifest.run_id.starts_with("github-actions:") {
            failures
                .push("qemu-guest two-node manifests must record a GitHub Actions run_id".into());
        }
        for (field, value) in [
            ("scope", manifest.scope.as_str()),
            ("artifact_path", manifest.artifact_path.as_str()),
            ("run_id", manifest.run_id.as_str()),
            ("source_ref", manifest.source_ref.as_str()),
            ("source", manifest.source.as_str()),
            ("residual_risk", manifest.residual_risk.as_str()),
        ] {
            validate_no_runner_local_reference(field, value, failures);
        }
    }

    let lower_risk = manifest.residual_risk.to_ascii_lowercase();
    for required in [
        "multi-process",
        "rdma",
        "production cluster",
        "storage-node runtime",
        "release-candidate",
    ] {
        if !lower_risk.contains(required) {
            failures.push(format!(
                "residual_risk must preserve two-node non-claim boundary `{required}`"
            ));
        }
    }
}

fn validate_outcome_blockers(
    outcome: EvidenceOutcome,
    blocking_issues: &[BlockingIssueRef],
    failures: &mut Vec<String>,
) {
    if outcome == EvidenceOutcome::Pass && !blocking_issues.is_empty() {
        failures.push("outcome `pass` must not carry blocking_issues".into());
    }
}

fn validate_relative_artifact_path(path: &str, failures: &mut Vec<String>) {
    validate_required_text("artifact_path", path, failures);
    if path.contains("://") {
        failures.push("artifact_path must be relative, not a URL".to_string());
    }
    if path.starts_with('~') || is_windows_absolute_path(path) {
        failures.push("artifact_path must be relative".to_string());
    }
    if path.contains('$') || path.contains('`') {
        failures.push(
            "artifact_path must not contain shell interpolation or secret expressions".into(),
        );
    }
    validate_no_runner_local_reference("artifact_path", path, failures);

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

fn validate_required_text(field: &str, value: &str, failures: &mut Vec<String>) {
    if value.trim().is_empty() {
        failures.push(format!("{field} must not be empty"));
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("${{ secrets.") || lower.contains("secrets.") {
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
            "generated_at must be a reviewable RFC3339-style timestamp such as 2026-06-28T21:00:00Z"
                .to_string(),
        );
    }
}

fn validate_no_runner_local_reference(field: &str, value: &str, failures: &mut Vec<String>) {
    let lower = value.to_ascii_lowercase();
    for forbidden in [
        "/tmp/",
        "/var/tmp/",
        "/root/",
        "/home/",
        "c:\\",
        "${{",
        "`",
        "secrets.",
    ] {
        if lower.contains(forbidden) {
            failures.push(format!(
                "{field} must not contain runner-local paths, shell interpolation, or secrets"
            ));
            return;
        }
    }
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_input<'a>(artifact: &'a [u8]) -> DeterministicHarnessManifestInput<'a> {
        DeterministicHarnessManifestInput {
            claim_binding: ClaimBinding::NonClaimScope(TWO_NODE_DETERMINISTIC_NON_CLAIM_SCOPE),
            artifact_path: "validation/artifacts/two-node/deterministic-loopback.json",
            artifact_bytes: artifact,
            fixture_id: "two-node-state-transfer-seed-42",
            source_ref: "refs/heads/gpt2/issue-1487-two-node-harness-manifests",
            generated_at: "2026-06-28T21:00:00Z",
            outcome: EvidenceOutcome::Pass,
            blocking_issues: Vec::new(),
        }
    }

    fn github_actions_ref() -> GitHubActionsArtifactRef<'static> {
        GitHubActionsArtifactRef {
            workflow: "Focused two-node QEMU",
            run_id: "28298370275",
            run_attempt: "1",
            run_url: "https://github.com/tidefs/tidefs/actions/runs/28298370275",
            artifact_name: "two-node-qemu-carrier-validation",
        }
    }

    #[test]
    fn deterministic_manifest_is_harness_only_non_claim() {
        let artifact = br#"{"harness":"tidefs-two-node-harness","carrier":"loopback"}"#;
        let manifest =
            EvidenceArtifactManifest::deterministic_harness(deterministic_input(artifact))
                .expect("deterministic manifest");

        assert_eq!(manifest.manifest_version, 2);
        assert_eq!(
            manifest.claim_id,
            "non-claim:two-node.harness.deterministic-loopback.v1"
        );
        assert_eq!(
            manifest.validation_tier,
            EvidenceValidationTier::HarnessOnly
        );
        assert_eq!(
            manifest.evidence_class,
            TWO_NODE_DETERMINISTIC_EVIDENCE_CLASS
        );
        assert!(manifest.residual_risk.contains("RDMA"));
        assert!(manifest.residual_risk.contains("storage-node runtime"));
        assert!(manifest.run_id.starts_with("deterministic-fixture:"));

        let json = manifest.to_json_pretty().expect("json");
        assert!(json.contains("\"validation_tier\": \"harness-only\""));
        assert!(json.contains("\"outcome\": \"pass\""));
    }

    #[test]
    fn deterministic_manifest_rejects_runtime_claim_binding() {
        let artifact = br#"{"harness":"tidefs-two-node-harness"}"#;
        let mut input = deterministic_input(artifact);
        input.claim_binding = ClaimBinding::ClaimId("rdma.production.storage-node.v1");
        let err = EvidenceArtifactManifest::deterministic_harness(input)
            .expect_err("runtime claim id must be rejected");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("cannot bind runtime/product claim")));
    }

    #[test]
    fn qemu_manifest_requires_github_actions_reference() {
        let artifact = br#"{"test":"tidefs-two-node-qemu-carrier-validation"}"#;
        let manifest = EvidenceArtifactManifest::qemu_tcp_carrier(QemuTcpCarrierManifestInput {
            claim_binding: ClaimBinding::NonClaimScope(TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE),
            artifact_path: "validation/artifacts/two-node/qemu-carrier-report.json",
            artifact_bytes: artifact,
            github_actions: github_actions_ref(),
            source_ref: "6d78ddfa4f64bc8643061b514dc911578fd4f53b5a4e92d7d5130db296b68d63",
            generated_at: "2026-06-28T21:00:00Z",
            outcome: EvidenceOutcome::Pass,
            qemu_guest_detected: true,
            blocking_issues: Vec::new(),
        })
        .expect("qemu manifest");

        assert_eq!(manifest.validation_tier, EvidenceValidationTier::QemuGuest);
        assert!(manifest.run_id.contains("github-actions:28298370275"));
        assert!(manifest
            .scope
            .contains("artifact_name=two-node-qemu-carrier-validation"));

        let json = manifest.to_json_pretty().expect("json");
        assert!(!json.contains("/tmp/"));
        assert!(!json.contains("secrets."));
        assert!(json.contains("\"validation_tier\": \"qemu-guest\""));
    }

    #[test]
    fn qemu_manifest_rejects_non_qemu_or_runner_local_paths() {
        let artifact = br#"{"test":"tidefs-two-node-qemu-carrier-validation"}"#;
        let no_guest = EvidenceArtifactManifest::qemu_tcp_carrier(QemuTcpCarrierManifestInput {
            claim_binding: ClaimBinding::NonClaimScope(TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE),
            artifact_path: "validation/artifacts/two-node/qemu-carrier-report.json",
            artifact_bytes: artifact,
            github_actions: github_actions_ref(),
            source_ref: "refs/heads/gpt2/issue-1487-two-node-harness-manifests",
            generated_at: "2026-06-28T21:00:00Z",
            outcome: EvidenceOutcome::Pass,
            qemu_guest_detected: false,
            blocking_issues: Vec::new(),
        })
        .expect_err("runtime tier requires qemu guest detection");
        assert!(no_guest.failures()[0].contains("qemu_guest_detected=true"));

        let bad_path = EvidenceArtifactManifest::qemu_tcp_carrier(QemuTcpCarrierManifestInput {
            claim_binding: ClaimBinding::NonClaimScope(TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE),
            artifact_path: "/tmp/carrier-report.json",
            artifact_bytes: artifact,
            github_actions: github_actions_ref(),
            source_ref: "refs/heads/gpt2/issue-1487-two-node-harness-manifests",
            generated_at: "2026-06-28T21:00:00Z",
            outcome: EvidenceOutcome::Pass,
            qemu_guest_detected: true,
            blocking_issues: Vec::new(),
        })
        .expect_err("runner-local artifact path must be rejected");
        assert!(bad_path
            .failures()
            .iter()
            .any(|failure| failure.contains("artifact_path must be relative")));
    }
}
