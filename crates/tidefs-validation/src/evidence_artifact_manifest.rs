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

pub const EVIDENCE_ARTIFACT_MANIFEST_VERSION: u32 = 1;
pub const EVIDENCE_ARTIFACT_DIGEST_ALGORITHM: &str = "blake3";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactManifest {
    pub manifest_version: u32,
    pub claim_id: String,
    pub evidence_class: String,
    pub validation_tier: ValidationTier,
    pub source: String,
    pub scope: String,
    pub artifact_path: String,
    pub content_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
        if self.source.trim().is_empty() {
            failures.push("source must not be empty".to_string());
        }
        if self.scope.trim().is_empty() {
            failures.push("scope must not be empty".to_string());
        }
        validate_relative_artifact_path(&self.artifact_path, &mut failures);
        validate_content_digest(&self.content_digest, &mut failures);

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
        let mut failures = Vec::new();
        validate_relative_artifact_path(&self.artifact_path, &mut failures);
        EvidenceArtifactManifestError::from_failures(failures)?;
        Ok(root.as_ref().join(&self.artifact_path))
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

fn validate_relative_artifact_path(path: &str, failures: &mut Vec<String>) {
    if path.trim().is_empty() {
        failures.push("artifact_path must not be empty".to_string());
        return;
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

fn canonical_content_digest(digest: &str) -> String {
    digest.to_ascii_lowercase()
}
