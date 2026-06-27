// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! xfstests evidence manifest.
//!
//! The xfstests workflow writes a per-target manifest alongside uploaded
//! artifacts so later issue/PR reports can cite a machine-checkable evidence
//! record instead of only a workflow URL.
//!
//! This manifest records run identity, source provenance, target, requested
//! row set, artifact-relative result paths, timestamps, and evidence scope
//! (focused vs broad).  It is a run-level manifest, not a per-file digest
//! manifest like [`super::evidence_artifact_manifest::EvidenceArtifactManifest`].

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path};

pub const XFSTESTS_EVIDENCE_MANIFEST_VERSION: u32 = 1;

/// Valid xfstests targets.
const VALID_TARGETS: &[&str] = &["fuse", "kmod-smoke", "k7-vfs", "all"];

/// Evidence scope values.
const VALID_EVIDENCE_SCOPES: &[&str] = &["focused", "broad"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XfstestsEvidenceManifest {
    pub manifest_version: u32,

    /// GitHub Actions workflow name ("xfstests").
    pub workflow: String,

    /// GitHub Actions run id.
    pub run_id: String,

    /// GitHub Actions run attempt number.
    pub run_attempt: String,

    /// Git ref that was checked out (e.g. "refs/heads/master").
    pub source_ref: String,

    /// Full commit SHA that was checked out.
    pub source_sha: String,

    /// Matrix target: "fuse", "kmod-smoke", "k7-vfs", or "all".
    pub target: String,

    /// Evidence scope: "focused" for manual dispatches with explicit
    /// `tests`, "broad" for scheduled or `target=all` runs.
    pub evidence_scope: String,

    /// Requested test rows.  Empty for broad runs, populated for focused
    /// manual dispatches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<String>,

    /// Relative paths within the uploaded artifact directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_paths: Vec<String>,

    /// UTC timestamp when the run started (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,

    /// UTC timestamp when the run finished (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfstestsEvidenceManifestError {
    failures: Vec<String>,
}

impl XfstestsEvidenceManifestError {
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

impl fmt::Display for XfstestsEvidenceManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "xfstests evidence manifest validation failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for XfstestsEvidenceManifestError {}

impl XfstestsEvidenceManifest {
    pub fn validate(&self) -> Result<(), XfstestsEvidenceManifestError> {
        let mut failures = Vec::new();

        if self.manifest_version != XFSTESTS_EVIDENCE_MANIFEST_VERSION {
            failures.push(format!(
                "manifest_version must be {XFSTESTS_EVIDENCE_MANIFEST_VERSION}, found {}",
                self.manifest_version
            ));
        }

        if self.workflow.trim().is_empty() {
            failures.push("workflow must not be empty".to_string());
        }

        if self.run_id.trim().is_empty() {
            failures.push("run_id must not be empty".to_string());
        }

        if self.run_attempt.trim().is_empty() {
            failures.push("run_attempt must not be empty".to_string());
        }

        if self.source_ref.trim().is_empty() {
            failures.push("source_ref must not be empty".to_string());
        }

        if self.source_sha.trim().is_empty() {
            failures.push("source_sha must not be empty".to_string());
        } else if self.source_sha.len() != 40
            || !self.source_sha.bytes().all(|b| b.is_ascii_hexdigit())
        {
            failures.push("source_sha must be a 40-character hex SHA".to_string());
        }

        if !VALID_TARGETS.contains(&self.target.as_str()) {
            failures.push(format!(
                "target must be one of [{}], found `{}`",
                VALID_TARGETS.join(", "),
                self.target
            ));
        }

        if !VALID_EVIDENCE_SCOPES.contains(&self.evidence_scope.as_str()) {
            failures.push(format!(
                "evidence_scope must be one of [{}], found `{}`",
                VALID_EVIDENCE_SCOPES.join(", "),
                self.evidence_scope
            ));
        }

        match self.evidence_scope.as_str() {
            "focused" if self.tests.is_empty() => {
                failures.push("evidence_scope=focused requires a non-empty tests list".to_string())
            }
            "broad" if !self.tests.is_empty() => {
                failures.push("evidence_scope=broad requires an empty tests list".to_string());
            }
            _ => {}
        }

        for test in &self.tests {
            if test.trim().is_empty() {
                failures.push("tests must not contain empty entries".to_string());
                break;
            }
        }

        for path in &self.artifact_paths {
            validate_relative_artifact_path(path, &mut failures);
        }

        XfstestsEvidenceManifestError::from_failures(failures)
    }

    pub fn to_json_pretty(&self) -> Result<String, XfstestsEvidenceManifestError> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|error| {
            XfstestsEvidenceManifestError::single(format!("serialize manifest JSON: {error}"))
        })
    }
}

fn validate_relative_artifact_path(path: &str, failures: &mut Vec<String>) {
    if path.trim().is_empty() {
        failures.push("artifact_paths must not contain empty entries".to_string());
        return;
    }

    let parsed = Path::new(path);
    if parsed.is_absolute() {
        failures.push(format!("artifact_paths must be relative, found `{path}`"));
    }

    let mut has_normal = false;
    for component in parsed.components() {
        match component {
            Component::Normal(_) => has_normal = true,
            Component::CurDir => {}
            Component::ParentDir => {
                failures.push(format!(
                    "artifact_paths must not contain `..`, found `{path}`"
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                failures.push(format!("artifact_paths must be relative, found `{path}`"));
            }
        }
    }

    if !has_normal {
        failures.push(format!("artifact_paths must name files, found `{path}`"));
    }
}

pub fn parse_xfstests_evidence_manifest_json(
    text: &str,
) -> Result<XfstestsEvidenceManifest, XfstestsEvidenceManifestError> {
    let manifest = serde_json::from_str::<XfstestsEvidenceManifest>(text).map_err(|error| {
        XfstestsEvidenceManifestError::single(format!(
            "manifest JSON does not match schema: {error}"
        ))
    })?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn load_xfstests_evidence_manifest_json_path(
    path: impl AsRef<Path>,
) -> Result<XfstestsEvidenceManifest, XfstestsEvidenceManifestError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| {
        XfstestsEvidenceManifestError::single(format!("read `{}`: {error}", path.display()))
    })?;
    parse_xfstests_evidence_manifest_json(&text)
}
