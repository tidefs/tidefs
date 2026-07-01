// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel fsync/syncfs durability evidence manifest support.
//!
//! The kernel fsync validation workflow exercises fsync(2), fdatasync(2),
//! and syncfs(2) against the mounted TideFS kernel filesystem across a
//! QEMU power-loss cycle.  This module provides the claim identity,
//! evidence class, and manifest construction helpers so the workflow can
//! emit a `validation/claims.toml`-compatible evidence manifest that the
//! `Focused Claim Validation` `validate-evidence-manifest` path can
//! check without scraping workflow logs or running QEMU.

use crate::evidence_artifact_manifest::{
    content_digest_for_bytes, EvidenceArtifactManifest, EVIDENCE_ARTIFACT_MANIFEST_VERSION,
    MISSING_EVIDENCE_CONTENT_DIGEST,
};
use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;

/// Claim identity for kernel fsync/syncfs durability rows.
pub const KERNEL_FSYNC_EVIDENCE_CLAIM_ID: &str = "kernel.fsync.durability.v1";

/// Evidence class recorded in the manifest.
pub const KERNEL_FSYNC_EVIDENCE_CLASS: &str = "runtime-kernel-fsync-validation";

/// Human-readable source label.
pub const KERNEL_FSYNC_EVIDENCE_SOURCE: &str = "kernel-fsync-validation";

/// Evidence scope tag.
pub const KERNEL_FSYNC_EVIDENCE_SCOPE: &str =
    "kernel-fsync-syncfs-durability-across-qemu-power-loss-cycle";

/// The validation tier for kernel fsync evidence.
pub const KERNEL_FSYNC_EVIDENCE_TIER: ValidationTier = ValidationTier::FullKernelNoDaemon;

/// Filename of the primary evidence artifact (summary.env).
pub const KERNEL_FSYNC_SUMMARY_FILENAME: &str = "summary.env";

/// Build an [`EvidenceArtifactManifest`] for a kernel fsync validation run.
///
/// The `summary_env_bytes` should be the full content of the
/// `summary.env` file produced by the validation script.  Callers that
/// cannot read the file (timed-out or missing summary) should pass
/// `None` and this function will write a manifest whose scope and
/// artifact path indicate the missing-summary condition.
///
/// `summary_artifact_path` and `log_artifact_paths` should be relative to
/// the uploaded artifact directory.
pub fn build_kernel_fsync_evidence_manifest(
    summary_env_bytes: Option<&[u8]>,
    generated_at: &str,
    workflow_run_id: &str,
    source_ref: &str,
    timeout_seconds: &str,
    pool_size_mb: &str,
    summary_artifact_path: &str,
    log_artifact_paths: &str,
    summary_exists: bool,
    passed: u32,
    failed: u32,
    blocked: u32,
) -> EvidenceArtifactManifest {
    let summary_artifact_path = if summary_artifact_path.is_empty() {
        KERNEL_FSYNC_SUMMARY_FILENAME
    } else {
        summary_artifact_path
    };
    let log_artifact_paths = if log_artifact_paths.is_empty() {
        "none"
    } else {
        log_artifact_paths
    };

    let (artifact_path, content_digest, scope_suffix) = match summary_env_bytes {
        Some(bytes) => {
            let digest = content_digest_for_bytes(bytes);
            (summary_artifact_path.to_string(), digest, String::new())
        }
        None => {
            (
                format!("{KERNEL_FSYNC_SUMMARY_FILENAME}.missing"),
                MISSING_EVIDENCE_CONTENT_DIGEST.to_string(),
                format!(
                    " (summary missing: run={workflow_run_id} source={source_ref} timeout={timeout_seconds}s pool={pool_size_mb}MB)"
                ),
            )
        }
    };

    let status_label = if !summary_exists || summary_env_bytes.is_none() {
        "no-summary"
    } else if failed > 0 {
        "fail"
    } else if blocked > 0 {
        "blocked"
    } else if passed > 0 {
        "pass"
    } else {
        "no-result"
    };
    let outcome = kernel_fsync_outcome(
        summary_exists,
        summary_env_bytes.is_some(),
        passed,
        failed,
        blocked,
    );

    let scope = format!(
        "{KERNEL_FSYNC_EVIDENCE_SCOPE} status={status_label} passed={passed} failed={failed} blocked={blocked} run={workflow_run_id} source={source_ref} timeout={timeout_seconds}s pool={pool_size_mb}MB summary_path={artifact_path} log_paths={log_artifact_paths}{scope_suffix}"
    );
    let residual_risk = format!(
        "Kernel fsync evidence is bounded to fsync/syncfs durability across one QEMU power-loss validation row with timeout={timeout_seconds}s and pool={pool_size_mb}MB; it does not close broader mounted kernel, xfstests, RDMA, or release-candidate evidence."
    );

    EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: KERNEL_FSYNC_EVIDENCE_CLAIM_ID.to_string(),
        evidence_class: KERNEL_FSYNC_EVIDENCE_CLASS.to_string(),
        validation_tier: KERNEL_FSYNC_EVIDENCE_TIER,
        scope,
        artifact_path,
        content_digest,
        run_id: workflow_run_id.to_string(),
        source_ref: source_ref.to_string(),
        outcome,
        residual_risk,
        source: KERNEL_FSYNC_EVIDENCE_SOURCE.to_string(),
        generated_at: generated_at.to_string(),
        blocking_issues: Vec::new(),
    }
}

/// Build a manifest for the QEMU Smoke `kernel-fsync-validation` target.
///
/// The QEMU Smoke runner exercises the same validation script but is not
/// the authoritative claims-gate source; its manifest records that the
/// standalone `kernel-fsync-validation` workflow owns the evidence.  The
/// artifact paths should be relative to the uploaded artifact directory.
pub fn build_qemu_smoke_kernel_fsync_manifest(
    summary_env_bytes: Option<&[u8]>,
    generated_at: &str,
    workflow_run_id: &str,
    source_ref: &str,
    summary_artifact_path: &str,
    log_artifact_paths: &str,
) -> EvidenceArtifactManifest {
    let summary_artifact_path = if summary_artifact_path.is_empty() {
        KERNEL_FSYNC_SUMMARY_FILENAME
    } else {
        summary_artifact_path
    };
    let log_artifact_paths = if log_artifact_paths.is_empty() {
        "none"
    } else {
        log_artifact_paths
    };

    let (artifact_path, content_digest) = match summary_env_bytes {
        Some(bytes) => {
            let digest = content_digest_for_bytes(bytes);
            (summary_artifact_path.to_string(), digest)
        }
        None => (
            format!("{KERNEL_FSYNC_SUMMARY_FILENAME}.missing"),
            MISSING_EVIDENCE_CONTENT_DIGEST.to_string(),
        ),
    };

    let scope = format!(
        "{KERNEL_FSYNC_EVIDENCE_SCOPE} source=qemu-smoke (claims-gate authority is standalone kernel-fsync-validation workflow) run={workflow_run_id} ref={source_ref} summary_path={artifact_path} log_paths={log_artifact_paths}"
    );
    let outcome = kernel_fsync_outcome_from_summary(summary_env_bytes);

    EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: KERNEL_FSYNC_EVIDENCE_CLAIM_ID.to_string(),
        evidence_class: KERNEL_FSYNC_EVIDENCE_CLASS.to_string(),
        validation_tier: KERNEL_FSYNC_EVIDENCE_TIER,
        scope,
        artifact_path,
        content_digest,
        run_id: workflow_run_id.to_string(),
        source_ref: source_ref.to_string(),
        outcome,
        residual_risk: "QEMU Smoke kernel-fsync output is diagnostic; the standalone kernel-fsync-validation workflow remains the claims-gate authority, and this artifact does not broaden runtime coverage by itself.".to_string(),
        source: "qemu-smoke-kernel-fsync-validation".to_string(),
        generated_at: generated_at.to_string(),
        blocking_issues: Vec::new(),
    }
}

fn kernel_fsync_outcome(
    summary_exists: bool,
    summary_bytes_present: bool,
    passed: u32,
    failed: u32,
    blocked: u32,
) -> ValidationStatus {
    if !summary_exists || !summary_bytes_present {
        ValidationStatus::HarnessFail
    } else if failed > 0 {
        ValidationStatus::ProductFail
    } else if blocked > 0 {
        ValidationStatus::EnvironmentRefusal
    } else if passed > 0 {
        ValidationStatus::Pass
    } else {
        ValidationStatus::HarnessFail
    }
}

fn kernel_fsync_outcome_from_summary(summary_env_bytes: Option<&[u8]>) -> ValidationStatus {
    let Some(bytes) = summary_env_bytes else {
        return ValidationStatus::HarnessFail;
    };
    let text = String::from_utf8_lossy(bytes);
    if text.lines().any(|line| line == "TIDEFS_FSYNC_STATUS=PASS") {
        ValidationStatus::Pass
    } else if text.lines().any(|line| line == "TIDEFS_FSYNC_STATUS=FAIL") {
        ValidationStatus::ProductFail
    } else if text
        .lines()
        .any(|line| line == "TIDEFS_FSYNC_STATUS=BLOCKED")
    {
        ValidationStatus::EnvironmentRefusal
    } else {
        ValidationStatus::HarnessFail
    }
}

/// Return the recommended manifest output filename.
#[must_use]
pub fn kernel_fsync_evidence_manifest_filename() -> &'static str {
    "evidence-manifest.json"
}

/// Return the relative artifact path for the summary file.
#[must_use]
pub fn summary_artifact_path() -> &'static str {
    KERNEL_FSYNC_SUMMARY_FILENAME
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_artifact_manifest::parse_evidence_artifact_manifest_json;

    #[test]
    fn build_manifest_pass() {
        let summary = b"TIDEFS_FSYNC_STATUS=PASS\nTIDEFS_FSYNC_PASSED=12\nTIDEFS_FSYNC_FAILED=0\nTIDEFS_FSYNC_BLOCKED=0\n";
        let manifest = build_kernel_fsync_evidence_manifest(
            Some(summary),
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "600",
            "256",
            "validation-20260621T000000Z-1/summary.env",
            "validation-20260621T000000Z-1/phase1.log,validation-20260621T000000Z-1/phase2.log",
            true,
            12,
            0,
            0,
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert_eq!(parsed.claim_id, KERNEL_FSYNC_EVIDENCE_CLAIM_ID);
        assert!(parsed.scope.contains("status=pass"));
        assert_eq!(
            parsed.artifact_path,
            "validation-20260621T000000Z-1/summary.env"
        );
        assert_eq!(parsed.run_id, "12345");
        assert_eq!(parsed.source_ref, "abc1234");
        assert_eq!(parsed.outcome, ValidationStatus::Pass);
        assert!(parsed.residual_risk.contains("bounded"));
        assert!(parsed
            .scope
            .contains("summary_path=validation-20260621T000000Z-1/summary.env"));
        assert!(parsed.scope.contains(
            "log_paths=validation-20260621T000000Z-1/phase1.log,validation-20260621T000000Z-1/phase2.log"
        ));
    }

    #[test]
    fn build_manifest_fail() {
        let summary = b"TIDEFS_FSYNC_STATUS=FAIL\nTIDEFS_FSYNC_PASSED=10\nTIDEFS_FSYNC_FAILED=2\nTIDEFS_FSYNC_BLOCKED=0\n";
        let manifest = build_kernel_fsync_evidence_manifest(
            Some(summary),
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "600",
            "256",
            "summary.env",
            "phase1.log,phase2.log",
            true,
            10,
            2,
            0,
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.scope.contains("status=fail"));
        assert_eq!(parsed.outcome, ValidationStatus::ProductFail);
    }

    #[test]
    fn build_manifest_blocked() {
        let summary = b"TIDEFS_FSYNC_STATUS=BLOCKED\nTIDEFS_FSYNC_PASSED=0\nTIDEFS_FSYNC_FAILED=0\nTIDEFS_FSYNC_BLOCKED=1\n";
        let manifest = build_kernel_fsync_evidence_manifest(
            Some(summary),
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "600",
            "256",
            "summary.env",
            "phase1.log,phase2.log",
            true,
            0,
            0,
            1,
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.scope.contains("status=blocked"));
        assert_eq!(parsed.outcome, ValidationStatus::EnvironmentRefusal);
    }

    #[test]
    fn build_manifest_missing_summary() {
        let manifest = build_kernel_fsync_evidence_manifest(
            None,
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "600",
            "256",
            "summary.env",
            "none",
            false,
            0,
            0,
            0,
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.scope.contains("no-summary"));
        assert!(parsed.artifact_path.contains(".missing"));
        assert_eq!(parsed.content_digest, MISSING_EVIDENCE_CONTENT_DIGEST);
        assert_eq!(parsed.outcome, ValidationStatus::HarnessFail);
    }

    #[test]
    fn build_manifest_no_result() {
        let summary = b"TIDEFS_FSYNC_STATUS=UNKNOWN\nTIDEFS_FSYNC_PASSED=0\nTIDEFS_FSYNC_FAILED=0\nTIDEFS_FSYNC_BLOCKED=0\n";
        let manifest = build_kernel_fsync_evidence_manifest(
            Some(summary),
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "600",
            "256",
            "summary.env",
            "phase1.log,phase2.log",
            true,
            0,
            0,
            0,
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.scope.contains("status=no-result"));
        assert_eq!(parsed.outcome, ValidationStatus::HarnessFail);
    }

    #[test]
    fn qemu_smoke_manifest_notes_authority() {
        let summary = b"TIDEFS_FSYNC_STATUS=PASS\n";
        let manifest = build_qemu_smoke_kernel_fsync_manifest(
            Some(summary),
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "validation-20260621T000000Z-1/summary.env",
            "validation-20260621T000000Z-1/phase1.log,validation-20260621T000000Z-1/phase2.log",
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.scope.contains("qemu-smoke"));
        assert!(parsed.scope.contains("claims-gate authority"));
        assert!(parsed
            .scope
            .contains("summary_path=validation-20260621T000000Z-1/summary.env"));
        assert!(parsed.scope.contains(
            "log_paths=validation-20260621T000000Z-1/phase1.log,validation-20260621T000000Z-1/phase2.log"
        ));
        assert_eq!(parsed.source, "qemu-smoke-kernel-fsync-validation");
        assert_eq!(parsed.outcome, ValidationStatus::Pass);
    }

    #[test]
    fn qemu_smoke_missing_summary_is_harness_failure() {
        let manifest = build_qemu_smoke_kernel_fsync_manifest(
            None,
            "2026-06-21T00:00:00Z",
            "12345",
            "abc1234",
            "summary.env",
            "phase1.log,phase2.log",
        );
        let json = manifest.to_json_pretty().expect("serialize manifest");
        let parsed = parse_evidence_artifact_manifest_json(&json).expect("round-trip parse");
        assert!(parsed.artifact_path.contains(".missing"));
        assert_eq!(parsed.content_digest, MISSING_EVIDENCE_CONTENT_DIGEST);
        assert_eq!(parsed.outcome, ValidationStatus::HarnessFail);
    }

    #[test]
    fn constants_are_non_empty() {
        assert!(!KERNEL_FSYNC_EVIDENCE_CLAIM_ID.is_empty());
        assert!(!KERNEL_FSYNC_EVIDENCE_CLASS.is_empty());
        assert!(!KERNEL_FSYNC_EVIDENCE_SOURCE.is_empty());
        assert!(!KERNEL_FSYNC_EVIDENCE_SCOPE.is_empty());
        assert!(!KERNEL_FSYNC_SUMMARY_FILENAME.is_empty());
        assert_eq!(
            KERNEL_FSYNC_EVIDENCE_TIER,
            ValidationTier::FullKernelNoDaemon
        );
    }
}
