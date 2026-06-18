// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;

use tidefs_validation::evidence_artifact_manifest::{
    content_digest_for_bytes, parse_evidence_artifact_manifest_json, BlockingIssueRef,
    EvidenceArtifactManifest,
};
use tidefs_validation::validation_schema::ValidationTier;

fn valid_manifest(payload: &[u8], artifact_path: impl Into<String>) -> EvidenceArtifactManifest {
    EvidenceArtifactManifest {
        manifest_version: 1,
        claim_id: "local.vfs.write_fsync_crash.v1".to_string(),
        evidence_class: "model-crash-matrix".to_string(),
        validation_tier: ValidationTier::SourceModel,
        source: "tidefs-crash-oracle".to_string(),
        scope: "model-only".to_string(),
        artifact_path: artifact_path.into(),
        content_digest: content_digest_for_bytes(payload),
        generated_at: Some("2026-06-18T00:00:00Z".to_string()),
        blocking_issues: vec![BlockingIssueRef {
            repo: Some("tidefs/tidefs".to_string()),
            number: 486,
            reason: Some("runtime crash evidence is owned separately".to_string()),
        }],
    }
}

fn assert_failure_contains(
    result: Result<
        EvidenceArtifactManifest,
        tidefs_validation::evidence_artifact_manifest::EvidenceArtifactManifestError,
    >,
    needle: &str,
) {
    let error = result.expect_err("manifest should be rejected");
    assert!(
        error
            .failures()
            .iter()
            .any(|failure| failure.contains(needle)),
        "expected failure containing `{needle}`, got {:?}",
        error.failures()
    );
}

#[test]
fn artifact_manifest_json_roundtrip_and_digest_verification() {
    let tempdir = tempfile::tempdir().unwrap();
    let artifact_path = "validation/artifacts/crash-oracle/model-crash-matrices.json";
    let payload = br#"{"report_version":1,"kind":"model-only"}"#;
    let full_path = tempdir.path().join(artifact_path);
    fs::create_dir_all(full_path.parent().unwrap()).unwrap();
    fs::write(&full_path, payload).unwrap();

    let manifest = valid_manifest(payload, artifact_path);
    let json = manifest.to_json_pretty().unwrap();
    let parsed = parse_evidence_artifact_manifest_json(&json).unwrap();

    assert_eq!(parsed, manifest);
    parsed.verify_artifact_digest(tempdir.path()).unwrap();
}

#[test]
fn artifact_manifest_rejects_missing_claim_id() {
    let json = r#"{
      "manifest_version": 1,
      "evidence_class": "model-crash-matrix",
      "validation_tier": "source-model",
      "source": "tidefs-crash-oracle",
      "scope": "model-only",
      "artifact_path": "validation/artifacts/crash-oracle/model-crash-matrices.json",
      "content_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000000"
    }"#;

    assert_failure_contains(
        parse_evidence_artifact_manifest_json(json),
        "missing field `claim_id`",
    );
}

#[test]
fn artifact_manifest_rejects_empty_evidence_class() {
    let mut manifest = valid_manifest(b"{}", "validation/artifacts/crash-oracle/model.json");
    manifest.evidence_class.clear();
    let error = manifest.validate().expect_err("empty class should fail");

    assert!(
        error
            .failures()
            .iter()
            .any(|failure| failure == "evidence_class must not be empty"),
        "unexpected failures: {:?}",
        error.failures()
    );
}

#[test]
fn artifact_manifest_rejects_unknown_validation_tier() {
    let json = r#"{
      "manifest_version": 1,
      "claim_id": "local.vfs.write_fsync_crash.v1",
      "evidence_class": "model-crash-matrix",
      "validation_tier": "runtime-ish",
      "source": "tidefs-crash-oracle",
      "scope": "model-only",
      "artifact_path": "validation/artifacts/crash-oracle/model-crash-matrices.json",
      "content_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000000"
    }"#;

    assert_failure_contains(
        parse_evidence_artifact_manifest_json(json),
        "unknown variant",
    );
}

#[test]
fn artifact_manifest_rejects_digest_mismatch() {
    let tempdir = tempfile::tempdir().unwrap();
    let artifact_path = "validation/artifacts/crash-oracle/model-crash-matrices.json";
    let full_path = tempdir.path().join(artifact_path);
    fs::create_dir_all(full_path.parent().unwrap()).unwrap();
    fs::write(&full_path, br#"{"report_version":1}"#).unwrap();

    let mut manifest = valid_manifest(b"different payload", artifact_path);
    manifest.content_digest =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let error = manifest
        .verify_artifact_digest(tempdir.path())
        .expect_err("digest mismatch should fail");

    assert!(
        error
            .failures()
            .iter()
            .any(|failure| failure.contains("content_digest mismatch")),
        "unexpected failures: {:?}",
        error.failures()
    );
}

#[test]
fn artifact_manifest_rejects_artifact_path_mismatch() {
    let tempdir = tempfile::tempdir().unwrap();
    let payload = br#"{"report_version":1}"#;
    let actual_path = tempdir
        .path()
        .join("validation/artifacts/crash-oracle/model-crash-matrices.json");
    fs::create_dir_all(actual_path.parent().unwrap()).unwrap();
    fs::write(&actual_path, payload).unwrap();

    let manifest = valid_manifest(payload, "validation/artifacts/crash-oracle/missing.json");
    let error = manifest
        .verify_artifact_digest(tempdir.path())
        .expect_err("path mismatch should fail");

    assert!(
        error
            .failures()
            .iter()
            .any(|failure| failure.contains("read artifact_path")),
        "unexpected failures: {:?}",
        error.failures()
    );
}
