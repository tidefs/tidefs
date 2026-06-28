// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! EvidenceArtifactManifest helpers for crash-oracle artifacts.
//!
//! The crash-oracle artifacts are shared by multiple claims, while the
//! manifest schema intentionally binds each record to one claim id. Callers
//! should emit one manifest per claim/evidence-class requirement rather than
//! using one artifact-wide manifest for every claim.

use std::fs;
use std::path::Path;

use tidefs_validation::evidence_artifact_manifest::{
    content_digest_for_bytes, content_digest_for_path, BlockingIssueRef, EvidenceArtifactManifest,
    EvidenceArtifactManifestError, EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use tidefs_validation::validation_schema::ValidationTier;
use tidefs_validation::validation_status::ValidationStatus;

use crate::CrashOracleError;

pub const MODEL_CRASH_MATRICES_ARTIFACT_PATH: &str =
    "validation/artifacts/crash-oracle/model-crash-matrices.json";
pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_ARTIFACT_PATH: &str =
    "validation/artifacts/crash-oracle/local-vfs-write-fsync-runtime-crash.json";
pub const LOCAL_VFS_RENAME_RUNTIME_ARTIFACT_PATH: &str =
    "validation/artifacts/crash-oracle/local-vfs-rename-crash-runtime.json";
pub const CLAIMS_GATE_REVIEW_ARTIFACT_PATH: &str =
    "validation/artifacts/crash-oracle/claims-gate-review.toml";

pub const MODEL_CRASH_MATRIX_EVIDENCE_CLASS: &str = "model-crash-matrix";
pub const RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS: &str = "runtime-crash-oracle";
pub const RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS: &str =
    "runtime-namespace-crash-artifact";
pub const CLAIMS_GATE_REVIEW_EVIDENCE_CLASS: &str = "claims-gate-review";

pub const MODEL_CRASH_MATRIX_SCOPE: &str =
    "bounded model-only crash matrix; no mounted runtime crash injection";
pub const LOCAL_VFS_WRITE_FSYNC_RUNTIME_SCOPE: &str =
    "bounded local VFS write -> fsync -> read -> crash/recover runtime path";
pub const LOCAL_VFS_RENAME_RUNTIME_SCOPE: &str =
    "bounded local VFS rename -> fsync -> read -> crash/recover runtime path";
pub const CLAIMS_GATE_REVIEW_SCOPE: &str = "model-runtime-boundary-review";

pub const CRASH_ORACLE_SOURCE: &str = "tidefs-crash-oracle";
pub const LOCAL_VFS_RUNTIME_SOURCE: &str = "tidefs-local-filesystem";
pub const CLAIMS_GATE_SOURCE: &str = "claims-gate";

#[derive(Clone, Debug)]
pub struct CrashEvidenceManifestInput {
    pub claim_id: String,
    pub evidence_class: String,
    pub validation_tier: ValidationTier,
    pub scope: String,
    pub artifact_path: String,
    pub run_id: String,
    pub source_ref: String,
    pub outcome: ValidationStatus,
    pub residual_risk: String,
    pub source: String,
    pub generated_at: String,
    pub blocking_issues: Vec<BlockingIssueRef>,
}

impl CrashEvidenceManifestInput {
    #[must_use]
    pub fn source_model(
        claim_id: impl Into<String>,
        evidence_class: impl Into<String>,
        scope: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            evidence_class: evidence_class.into(),
            validation_tier: ValidationTier::SourceModel,
            scope: scope.into(),
            artifact_path: artifact_path.into(),
            run_id: "deterministic-fixture:crash-oracle-source-model-v1".to_string(),
            source_ref: String::new(),
            outcome: ValidationStatus::Pass,
            residual_risk:
                "Source-model crash evidence does not prove mounted runtime crash safety."
                    .to_string(),
            source: CRASH_ORACLE_SOURCE.to_string(),
            generated_at: String::new(),
            blocking_issues: Vec::new(),
        }
    }

    #[must_use]
    pub fn mounted_userspace(
        claim_id: impl Into<String>,
        evidence_class: impl Into<String>,
        scope: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            evidence_class: evidence_class.into(),
            validation_tier: ValidationTier::MountedUserspace,
            scope: scope.into(),
            artifact_path: artifact_path.into(),
            run_id: "deterministic-fixture:crash-oracle-mounted-userspace-v1".to_string(),
            source_ref: String::new(),
            outcome: ValidationStatus::Pass,
            residual_risk:
                "Mounted-userspace crash evidence is bounded to the exercised local VFS path."
                    .to_string(),
            source: LOCAL_VFS_RUNTIME_SOURCE.to_string(),
            generated_at: String::new(),
            blocking_issues: Vec::new(),
        }
    }
}

pub fn build_crash_evidence_manifest_for_bytes(
    input: CrashEvidenceManifestInput,
    artifact_bytes: &[u8],
) -> Result<EvidenceArtifactManifest, EvidenceArtifactManifestError> {
    let manifest = EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: input.claim_id,
        evidence_class: input.evidence_class,
        validation_tier: input.validation_tier,
        scope: input.scope,
        artifact_path: input.artifact_path,
        content_digest: content_digest_for_bytes(artifact_bytes),
        run_id: input.run_id,
        source_ref: input.source_ref,
        outcome: input.outcome,
        residual_risk: input.residual_risk,
        source: input.source,
        generated_at: input.generated_at,
        blocking_issues: input.blocking_issues,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn build_crash_evidence_manifest_for_path(
    root: impl AsRef<Path>,
    input: CrashEvidenceManifestInput,
) -> Result<EvidenceArtifactManifest, EvidenceArtifactManifestError> {
    let full_path = root.as_ref().join(&input.artifact_path);
    let digest = content_digest_for_path(&full_path)?;
    let manifest = EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: input.claim_id,
        evidence_class: input.evidence_class,
        validation_tier: input.validation_tier,
        scope: input.scope,
        artifact_path: input.artifact_path,
        content_digest: digest,
        run_id: input.run_id,
        source_ref: input.source_ref,
        outcome: input.outcome,
        residual_risk: input.residual_risk,
        source: input.source,
        generated_at: input.generated_at,
        blocking_issues: input.blocking_issues,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn write_crash_evidence_manifest_json(
    path: impl AsRef<Path>,
    manifest: &EvidenceArtifactManifest,
) -> Result<(), CrashOracleError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = manifest
        .to_json_pretty()
        .map_err(|err| CrashOracleError::Report(err.to_string()))?;
    fs::write(path, format!("{json}\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_at() -> String {
        "2026-06-28T18:30:00Z".to_string()
    }

    fn source_ref() -> String {
        "0e92fb4531d3812a7a7cc5a6c1ce1a616277956e".to_string()
    }

    #[test]
    fn source_model_manifest_binds_claim_tier_and_digest() {
        let mut input = CrashEvidenceManifestInput::source_model(
            crate::LOCAL_VFS_WRITE_FSYNC_CLAIM_ID,
            MODEL_CRASH_MATRIX_EVIDENCE_CLASS,
            MODEL_CRASH_MATRIX_SCOPE,
            MODEL_CRASH_MATRICES_ARTIFACT_PATH,
        );
        input.source_ref = source_ref();
        input.generated_at = generated_at();

        let manifest = build_crash_evidence_manifest_for_bytes(input, b"model artifact")
            .expect("valid model manifest");

        assert_eq!(manifest.claim_id, crate::LOCAL_VFS_WRITE_FSYNC_CLAIM_ID);
        assert_eq!(manifest.evidence_class, MODEL_CRASH_MATRIX_EVIDENCE_CLASS);
        assert_eq!(manifest.validation_tier, ValidationTier::SourceModel);
        assert_eq!(
            manifest.content_digest,
            content_digest_for_bytes(b"model artifact")
        );
        assert_eq!(manifest.source, CRASH_ORACLE_SOURCE);
        assert!(manifest.scope.contains("model-only"));
    }

    #[test]
    fn runtime_manifest_stays_mounted_userspace_scoped() {
        let mut input = CrashEvidenceManifestInput::mounted_userspace(
            crate::LOCAL_VFS_WRITE_FSYNC_CLAIM_ID,
            RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS,
            LOCAL_VFS_WRITE_FSYNC_RUNTIME_SCOPE,
            LOCAL_VFS_WRITE_FSYNC_RUNTIME_ARTIFACT_PATH,
        );
        input.source_ref = source_ref();
        input.generated_at = generated_at();

        let manifest = build_crash_evidence_manifest_for_bytes(input, b"runtime artifact")
            .expect("valid runtime manifest");

        assert_eq!(manifest.validation_tier, ValidationTier::MountedUserspace);
        assert_eq!(manifest.evidence_class, RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS);
        assert_eq!(manifest.source, LOCAL_VFS_RUNTIME_SOURCE);
        assert!(manifest.residual_risk.contains("local VFS path"));
    }

    #[test]
    fn pass_manifest_with_unresolved_blocker_fails_closed() {
        let mut input = CrashEvidenceManifestInput::source_model(
            crate::LOCAL_VFS_WRITE_FSYNC_CLAIM_ID,
            MODEL_CRASH_MATRIX_EVIDENCE_CLASS,
            MODEL_CRASH_MATRIX_SCOPE,
            MODEL_CRASH_MATRICES_ARTIFACT_PATH,
        );
        input.source_ref = source_ref();
        input.generated_at = generated_at();
        input.blocking_issues.push(BlockingIssueRef {
            repo: Some("tidefs/tidefs".to_string()),
            number: 1484,
            reason: Some("fixture blocker".to_string()),
        });

        let err = build_crash_evidence_manifest_for_bytes(input, b"model artifact")
            .expect_err("pass with blockers must fail");
        assert!(err
            .failures()
            .iter()
            .any(|failure| failure.contains("outcome `pass` must not carry blocking_issues")));
    }
}
