// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fs;
use std::path::{Path, PathBuf};

use tidefs_validation::evidence_artifact_manifest::{
    content_digest_for_bytes, parse_evidence_artifact_manifest_json, EvidenceArtifactManifest,
    EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use tidefs_validation::validation_schema::ValidationTier;
use tidefs_validation::validation_status::ValidationStatus;

fn valid_manifest(payload: &[u8], artifact_path: impl Into<String>) -> EvidenceArtifactManifest {
    EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: "local.vfs.write_fsync_crash.v1".to_string(),
        evidence_class: "model-crash-matrix".to_string(),
        validation_tier: ValidationTier::SourceModel,
        scope: "model-only".to_string(),
        artifact_path: artifact_path.into(),
        content_digest: content_digest_for_bytes(payload),
        run_id: "123456789/1".to_string(),
        source_ref: "774b48046851ee844284b62a484573597c96a013".to_string(),
        outcome: ValidationStatus::Pass,
        residual_risk: "Fixture covers schema validation only; it is not runtime proof."
            .to_string(),
        source: "tidefs-crash-oracle".to_string(),
        generated_at: "2026-06-18T00:00:00Z".to_string(),
        blocking_issues: Vec::new(),
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

fn collect_committed_artifact_files(root: &Path, files: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("walk {}: {error}", root.display()));
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()));
        if file_type.is_dir() {
            collect_committed_artifact_files(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

#[test]
fn committed_validation_artifacts_do_not_embed_scratch_paths() {
    const SCRATCH_PATH_NEEDLES: &[&[u8]] = &[
        b"/tmp/tidefs-validation",
        b"/root/ai/tmp/tidefs-validation",
    ];

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should live under crates/tidefs-validation");
    let artifacts_root = repo_root.join("validation/artifacts");

    let mut artifact_files = Vec::new();
    collect_committed_artifact_files(&artifacts_root, &mut artifact_files);

    let mut failures = Vec::new();
    for path in artifact_files {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!("read committed validation artifact {}: {error}", path.display())
        });
        for needle in SCRATCH_PATH_NEEDLES {
            if bytes.windows(needle.len()).any(|window| window == *needle) {
                let relative_path = path
                    .strip_prefix(repo_root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                failures.push(format!(
                    "{relative_path} embeds scratch path `{}`",
                    String::from_utf8_lossy(needle)
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "committed validation artifacts must be fixtures or promoted evidence, not scratch output:\n{}",
        failures.join("\n")
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
      "manifest_version": 2,
      "evidence_class": "model-crash-matrix",
      "validation_tier": "source-model",
      "source": "tidefs-crash-oracle",
      "scope": "model-only",
      "artifact_path": "validation/artifacts/crash-oracle/model-crash-matrices.json",
      "content_digest": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
      "run_id": "123456789/1",
      "source_ref": "774b48046851ee844284b62a484573597c96a013",
      "outcome": "pass",
      "residual_risk": "Fixture covers schema validation only.",
      "generated_at": "2026-06-18T00:00:00Z",
      "blocking_issues": []
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
      "manifest_version": 2,
      "claim_id": "local.vfs.write_fsync_crash.v1",
      "evidence_class": "model-crash-matrix",
      "validation_tier": "runtime-ish",
      "source": "tidefs-crash-oracle",
      "scope": "model-only",
      "artifact_path": "validation/artifacts/crash-oracle/model-crash-matrices.json",
      "content_digest": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
      "run_id": "123456789/1",
      "source_ref": "774b48046851ee844284b62a484573597c96a013",
      "outcome": "pass",
      "residual_risk": "Fixture covers schema validation only.",
      "generated_at": "2026-06-18T00:00:00Z",
      "blocking_issues": []
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
    manifest.content_digest = content_digest_for_bytes(b"different payload");
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
