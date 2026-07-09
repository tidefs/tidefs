// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tidefs_validation::evidence_artifact_manifest::{
    content_digest_for_bytes, is_runtime_artifact_path, parse_evidence_artifact_manifest_json,
    validate_artifact_path_shape, EvidenceArtifactManifest, EVIDENCE_ARTIFACT_MANIFEST_VERSION,
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

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should live under crates/tidefs-validation")
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn committed_repo_files(repo_root: &Path) -> BTreeSet<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("ls-files")
        .output()
        .expect("run git ls-files");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("git ls-files output should be UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn is_manifest_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".manifest.json"))
}

fn bytes_contain(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn normalize_json_unicode_slash_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = bytes.to_vec();
    let mut offset = 0;
    while let Some(relative_offset) = normalized[offset..]
        .windows(br"\u002F".len())
        .position(|window| window == br"\u002F")
    {
        let escape_offset = offset + relative_offset;
        normalized[escape_offset + br"\u002".len()] = b'f';
        offset = escape_offset + br"\u002F".len();
    }
    normalized
}

#[test]
fn runtime_artifact_classifier_is_token_based() {
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/ublk/started-export-admission-runtime.json"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/Runtime_Output.toml"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime-output.JSON"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime/output.json"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime-output.log"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime-output.txt"
    )));
    assert!(is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime/output"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/crash-oracle/model-crash-matrices.json"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/nonruntime-output.json"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/crash-oracle/runtime.manifest.json"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime/output.manifest.json"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/crash-oracle/runtime.MANIFEST.JSON"
    )));
    assert!(!is_runtime_artifact_path(Path::new(
        "validation/artifacts/kernel/runtime/output.Manifest.Json"
    )));
}

#[test]
fn runtime_artifact_manifest_paths_require_live_runtime_tier() {
    let payload = br#"{"report_version":1,"kind":"runtime"}"#;
    let mut manifest = valid_manifest(
        payload,
        "validation/artifacts/local-vfs/runtime-crash/runtime-summary.json",
    );

    let error = manifest
        .validate()
        .expect_err("runtime artifact path with source-model tier should fail");
    assert!(
        error.failures().iter().any(|failure| failure
            .contains("runtime artifact_path requires live-runtime validation_tier")),
        "expected live-runtime tier failure, got {:?}",
        error.failures()
    );

    manifest.validation_tier = ValidationTier::MountedUserspace;
    manifest
        .validate()
        .expect("runtime artifact path with live-runtime tier should pass");

    manifest.artifact_path = "validation/artifacts/local-vfs/summary.json".to_string();
    let error = manifest
        .validate()
        .expect_err("live-runtime tier with non-runtime artifact path should fail");
    assert!(
        error.failures().iter().any(|failure| failure
            .contains("live-runtime validation_tier requires runtime artifact_path")),
        "expected runtime artifact path failure, got {:?}",
        error.failures()
    );
}

#[test]
fn committed_validation_artifacts_do_not_embed_scratch_paths() {
    const SCRATCH_PATH_NEEDLES: &[(&[u8], &str)] = &[
        (b"/tmp/tidefs-validation", "/tmp/tidefs-validation"),
        (br"\/tmp\/tidefs-validation", r"\/tmp\/tidefs-validation"),
        (
            b"/root/ai/tmp/tidefs-validation",
            "/root/ai/tmp/tidefs-validation",
        ),
        (
            br"\/root\/ai\/tmp\/tidefs-validation",
            r"\/root\/ai\/tmp\/tidefs-validation",
        ),
    ];
    const JSON_UNICODE_SLASH_SCRATCH_PATH_NEEDLES: &[(&[u8], &str)] = &[
        (
            br"\u002ftmp\u002ftidefs-validation",
            r"\u002ftmp\u002ftidefs-validation",
        ),
        (
            br"\u002froot\u002fai\u002ftmp\u002ftidefs-validation",
            r"\u002froot\u002fai\u002ftmp\u002ftidefs-validation",
        ),
    ];

    let repo_root = repo_root();
    let artifacts_root = repo_root.join("validation/artifacts");

    let mut artifact_files = Vec::new();
    collect_committed_artifact_files(&artifacts_root, &mut artifact_files);

    let mut failures = Vec::new();
    for path in artifact_files {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "read committed validation artifact {}: {error}",
                path.display()
            )
        });
        for (needle, display) in SCRATCH_PATH_NEEDLES {
            if bytes_contain(&bytes, needle) {
                let relative_path = repo_relative_path(repo_root, &path);
                failures.push(format!("{relative_path} embeds scratch path `{display}`"));
            }
        }
        let normalized_bytes = normalize_json_unicode_slash_escapes(&bytes);
        for (needle, display) in JSON_UNICODE_SLASH_SCRATCH_PATH_NEEDLES {
            if bytes_contain(&normalized_bytes, needle) {
                let relative_path = repo_relative_path(repo_root, &path);
                failures.push(format!("{relative_path} embeds scratch path `{display}`"));
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
fn committed_evidence_manifests_verify_artifact_payloads() {
    let repo_root = repo_root();
    let artifacts_root = repo_root.join("validation/artifacts");

    let mut artifact_files = Vec::new();
    collect_committed_artifact_files(&artifacts_root, &mut artifact_files);

    let committed_files = committed_repo_files(repo_root);

    let mut failures = Vec::new();
    for path in artifact_files.iter().filter(|path| is_manifest_path(path)) {
        let manifest_path = repo_relative_path(repo_root, path);
        let text = fs::read_to_string(path).unwrap_or_else(|error| {
            panic!(
                "read committed validation manifest {}: {error}",
                path.display()
            )
        });
        let manifest = parse_evidence_artifact_manifest_json(&text).unwrap_or_else(|error| {
            panic!(
                "parse committed validation manifest {}: {:?}",
                path.display(),
                error.failures()
            )
        });

        if let Err(error) = validate_artifact_path_shape(&manifest.artifact_path) {
            failures.push(format!(
                "{manifest_path} has invalid artifact_path `{}`: {}",
                manifest.artifact_path,
                error.failures().join("; ")
            ));
            continue;
        }
        if is_manifest_path(Path::new(&manifest.artifact_path)) {
            failures.push(format!(
                "{manifest_path} points at manifest `{}` instead of an artifact payload",
                manifest.artifact_path
            ));
        }
        if !committed_files.contains(&manifest.artifact_path) {
            failures.push(format!(
                "{manifest_path} points at non-committed artifact payload `{}`",
                manifest.artifact_path
            ));
        }
        if let Err(error) = manifest.verify_artifact_digest(repo_root) {
            failures.push(format!(
                "{manifest_path} has invalid artifact digest: {}",
                error.failures().join("; ")
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "committed evidence manifests must match their artifact payloads:\n{}",
        failures.join("\n")
    );
}

#[test]
fn committed_runtime_artifacts_have_runtime_tier_manifests() {
    let repo_root = repo_root();
    let artifacts_root = repo_root.join("validation/artifacts");

    let mut artifact_files = Vec::new();
    collect_committed_artifact_files(&artifacts_root, &mut artifact_files);

    let committed_artifacts = artifact_files
        .iter()
        .filter(|path| !is_manifest_path(path))
        .map(|path| repo_relative_path(repo_root, path))
        .collect::<BTreeSet<_>>();
    let committed_runtime_artifacts = committed_artifacts
        .iter()
        .filter(|path| is_runtime_artifact_path(Path::new(path)))
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut failures = Vec::new();
    let mut live_runtime_artifacts = BTreeSet::new();
    let mut artifact_runtime_classes = BTreeMap::<String, BTreeSet<bool>>::new();
    for path in artifact_files.iter().filter(|path| is_manifest_path(path)) {
        let text = fs::read_to_string(path).unwrap_or_else(|error| {
            panic!(
                "read committed validation manifest {}: {error}",
                path.display()
            )
        });
        let manifest = parse_evidence_artifact_manifest_json(&text).unwrap_or_else(|error| {
            panic!(
                "parse committed validation manifest {}: {:?}",
                path.display(),
                error.failures()
            )
        });
        let artifact_path = Path::new(&manifest.artifact_path);
        if !is_manifest_path(artifact_path) && committed_artifacts.contains(&manifest.artifact_path)
        {
            artifact_runtime_classes
                .entry(manifest.artifact_path.clone())
                .or_default()
                .insert(manifest.validation_tier.is_live_runtime());
        }
        if manifest.validation_tier.is_live_runtime() {
            let manifest_path = repo_relative_path(repo_root, path);
            if is_manifest_path(artifact_path) {
                failures.push(format!(
                    "{manifest_path} is a live-runtime manifest pointing at manifest `{}`",
                    manifest.artifact_path
                ));
            }
            if !committed_artifacts.contains(&manifest.artifact_path) {
                failures.push(format!(
                    "{manifest_path} is a live-runtime manifest pointing at non-committed artifact `{}`",
                    manifest.artifact_path
                ));
            }
            if !is_runtime_artifact_path(Path::new(&manifest.artifact_path)) {
                failures.push(format!(
                    "{manifest_path} is a live-runtime manifest pointing at non-runtime artifact `{}`",
                    manifest.artifact_path
                ));
            }
            if let Err(error) = manifest.verify_artifact_digest(repo_root) {
                failures.push(format!(
                    "{manifest_path} has invalid live-runtime artifact digest: {}",
                    error.failures().join("; ")
                ));
            }
            live_runtime_artifacts.insert(manifest.artifact_path);
        }
    }

    for (artifact_path, runtime_classes) in artifact_runtime_classes {
        if runtime_classes.contains(&true) && runtime_classes.contains(&false) {
            failures.push(format!(
                "{artifact_path} has both live-runtime and non-runtime evidence manifests"
            ));
        }
    }

    for artifact_path in committed_runtime_artifacts {
        if !live_runtime_artifacts.contains(&artifact_path) {
            failures.push(format!(
                "{artifact_path} is unclassified runtime output missing v2 live-runtime evidence manifest"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "committed runtime artifacts must be promoted evidence:\n{}",
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
