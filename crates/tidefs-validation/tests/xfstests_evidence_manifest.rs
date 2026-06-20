// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use tidefs_validation::xfstests_evidence_manifest::{
    parse_xfstests_evidence_manifest_json, XfstestsEvidenceManifest,
    XFSTESTS_EVIDENCE_MANIFEST_VERSION,
};

fn valid_focused_manifest() -> XfstestsEvidenceManifest {
    XfstestsEvidenceManifest {
        manifest_version: XFSTESTS_EVIDENCE_MANIFEST_VERSION,
        workflow: "xfstests".to_string(),
        run_id: "1234567890".to_string(),
        run_attempt: "1".to_string(),
        source_ref: "refs/heads/master".to_string(),
        source_sha: "3d95619007e5fe03c02de84786b2ad0024439315".to_string(),
        target: "fuse".to_string(),
        evidence_scope: "focused".to_string(),
        tests: vec!["generic/001".to_string(), "generic/002".to_string()],
        artifact_paths: vec!["validation.json".to_string()],
        started_at: Some("2026-06-20T18:00:00Z".to_string()),
        finished_at: Some("2026-06-20T20:00:00Z".to_string()),
    }
}

fn valid_broad_manifest() -> XfstestsEvidenceManifest {
    XfstestsEvidenceManifest {
        manifest_version: XFSTESTS_EVIDENCE_MANIFEST_VERSION,
        workflow: "xfstests".to_string(),
        run_id: "1234567890".to_string(),
        run_attempt: "1".to_string(),
        source_ref: "refs/heads/master".to_string(),
        source_sha: "3d95619007e5fe03c02de84786b2ad0024439315".to_string(),
        target: "fuse".to_string(),
        evidence_scope: "broad".to_string(),
        tests: vec![],
        artifact_paths: vec!["validation.json".to_string()],
        started_at: None,
        finished_at: None,
    }
}

#[test]
fn focused_manifest_roundtrip() {
    let manifest = valid_focused_manifest();
    let json = manifest.to_json_pretty().unwrap();
    let parsed = parse_xfstests_evidence_manifest_json(&json).unwrap();
    assert_eq!(parsed, manifest);
}

#[test]
fn broad_manifest_roundtrip() {
    let manifest = valid_broad_manifest();
    let json = manifest.to_json_pretty().unwrap();
    let parsed = parse_xfstests_evidence_manifest_json(&json).unwrap();
    assert_eq!(parsed, manifest);
}

#[test]
fn broad_manifest_omits_empty_optional() {
    let manifest = valid_broad_manifest();
    let json = manifest.to_json_pretty().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(!obj.contains_key("tests"));
    assert!(!obj.contains_key("started_at"));
    assert!(!obj.contains_key("finished_at"));
}

#[test]
fn rejects_missing_workflow() {
    let mut manifest = valid_focused_manifest();
    manifest.workflow = String::new();
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("workflow")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_bad_sha_length() {
    let mut manifest = valid_focused_manifest();
    manifest.source_sha = "abc".to_string();
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("source_sha")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_non_hex_sha() {
    let mut manifest = valid_focused_manifest();
    manifest.source_sha = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("source_sha")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_unknown_target() {
    let mut manifest = valid_focused_manifest();
    manifest.target = "invalid".to_string();
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("target")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_unknown_evidence_scope() {
    let mut manifest = valid_focused_manifest();
    manifest.evidence_scope = "medium".to_string();
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("evidence_scope")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_focused_without_tests() {
    let mut manifest = valid_focused_manifest();
    manifest.tests = vec![];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("focused")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_empty_test_name() {
    let mut manifest = valid_focused_manifest();
    manifest.tests = vec!["generic/001".to_string(), " ".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("tests")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_empty_artifact_path() {
    let mut manifest = valid_focused_manifest();
    manifest.artifact_paths = vec!["validation.json".to_string(), " ".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures()
            .iter()
            .any(|f| f.contains("artifact_paths")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_absolute_artifact_path() {
    let mut manifest = valid_focused_manifest();
    manifest.artifact_paths = vec!["/tmp/validation.json".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("relative")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_parent_artifact_path_component() {
    let mut manifest = valid_focused_manifest();
    manifest.artifact_paths = vec!["../validation.json".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("..")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_artifact_path_without_file_name() {
    let mut manifest = valid_focused_manifest();
    manifest.artifact_paths = vec![".".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("name files")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn accepts_broad_without_tests() {
    let manifest = valid_broad_manifest();
    manifest.validate().unwrap();
}

#[test]
fn rejects_broad_with_tests() {
    let mut manifest = valid_broad_manifest();
    manifest.tests = vec!["generic/001".to_string()];
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("broad")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_invalid_manifest_version() {
    let mut manifest = valid_focused_manifest();
    manifest.manifest_version = 99;
    let err = manifest.validate().unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("manifest_version")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_unknown_fields() {
    let json = r#"{
        "manifest_version": 1,
        "workflow": "xfstests",
        "run_id": "123",
        "run_attempt": "1",
        "source_ref": "refs/heads/master",
        "source_sha": "3d95619007e5fe03c02de84786b2ad0024439315",
        "target": "fuse",
        "evidence_scope": "focused",
        "tests": ["generic/001"],
        "artifact_paths": ["validation.json"],
        "extra_field": "unexpected"
    }"#;
    let err = parse_xfstests_evidence_manifest_json(json).unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("unknown field")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn rejects_missing_required_fields() {
    let json = r#"{"manifest_version": 1}"#;
    let err = parse_xfstests_evidence_manifest_json(json).unwrap_err();
    assert!(
        err.failures().iter().any(|f| f.contains("workflow")),
        "{:?}",
        err.failures()
    );
}

#[test]
fn validates_all_known_targets() {
    for target in &["fuse", "kmod-smoke", "k7-vfs", "all"] {
        let mut manifest = valid_focused_manifest();
        manifest.target = (*target).to_string();
        manifest.validate().unwrap();
    }
}

#[test]
fn validates_all_known_evidence_scopes() {
    let mut manifest = valid_broad_manifest();
    manifest.evidence_scope = "broad".to_string();
    manifest.validate().unwrap();

    manifest.evidence_scope = "focused".to_string();
    manifest.tests = vec!["generic/001".to_string()];
    manifest.validate().unwrap();
}

#[test]
fn focused_manifest_preserves_test_list() {
    let manifest = valid_focused_manifest();
    assert_eq!(manifest.tests, vec!["generic/001", "generic/002"]);

    let json = manifest.to_json_pretty().unwrap();
    let parsed = parse_xfstests_evidence_manifest_json(&json).unwrap();
    assert_eq!(parsed.tests, vec!["generic/001", "generic/002"]);
}
