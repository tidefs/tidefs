// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use tidefs_validation::evidence_artifact_manifest::{
    load_evidence_artifact_manifest_json_path, BlockingIssueRef, EvidenceArtifactManifest,
};
use tidefs_validation::local_vfs_runtime_crash_artifact::{
    validate_local_vfs_rename_runtime_crash_artifact_path,
    validate_local_vfs_runtime_crash_artifact_path, LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS,
    LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS,
};
use tidefs_validation::ublk_completion_artifact::{
    validate_ublk_completion_artifact_path, UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS,
};
use tidefs_validation::ublk_started_export_admission_artifact::{
    validate_ublk_started_export_admission_artifact_path,
    UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS,
};
use tidefs_validation::validation_schema::ValidationTier;
use tidefs_validation::validation_status::ValidationStatus;

pub const CLAIMS_GATE_POLICY_SPEC: &str = "claims gate: publishing-facing TideFS docs must not claim current OpenZFS/Ceph successor, production-ready, POSIX-complete, distributed, kernelspace, RDMA data-path, or final distributed operator UAPI capability before matching proof exists; unreleased internal TideFS paths must not be framed as product compatibility or migration promises without a real external boundary; tidefsctl command classification/admission is the public operator/harness/diagnostic/prototype/removed boundary; validation/claims.toml is the stable claim registry authority";
pub const CLAIMS_GATE_REQUIRED_COMMAND: &str = "cargo run -p tidefs-xtask -- check-claims-gate";

pub const CLAIMS_GATE_SCANNED_DOCS: &[&str] = &[
    "README.md",
    "apps/README.md",
    "crates/README.md",
    "docs/00_user_requirements.md",
    "docs/BLAKE3_USAGE_POLICY.md",
    "docs/CLAIM_REGISTRY.md",
    "docs/CLAIMS_GATE_POLICY.md",
    "docs/GETTING_STARTED.md",
    "docs/INDEX.md",
    "docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md",
    "docs/PREVIEW_USER_MANUAL.md",
    "docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md",
    "docs/REVIEW_TODO_REGISTER.md",
    "docs/UNRELEASED_AUTHORITY_POLICY.md",
    "docs/WHOLE_REPO_REVIEW.md",
    "docs/workspace-package-classification.md",
];

pub const CLAIMS_GATE_SENSITIVE_PATTERNS: &[&str] = &[
    "openzfs/ceph successor",
    "openzfs and ceph successor",
    "successor to openzfs",
    "openzfs replacement",
    "ceph replacement",
    "production-ready",
    "production ready",
    "production-grade",
    "posix-complete",
    "kernelspace ready",
    "distributed storage",
    "rdma data path",
    "hardware-rdma claim",
    "full-kernel",
    "full kernel",
    "mounted device-level compression",
    "mounted device-level encryption",
    "mounted compression",
    "mounted encryption",
    "end-to-end mounted filesystem support",
    "final distributed operator uapi",
];

const CLAIMS_GATE_ALLOWED_FRAMES: &[&str] = &[
    "not",
    "no ",
    "none",
    "without",
    "until proof",
    "before proof",
    "prohibited",
    "future",
    "eventually",
    "ambition",
    "goal",
    "aspirational",
    "spec-draft",
    "not implemented",
    "not yet",
    "does not",
    "do not",
    "must not",
    "remains optional",
    "lacks",
    "needs",
    "after",
    "before any",
    "separate implementation",
    "does not currently",
    "residency invariant",
    "not yet full-kernel",
    "not full-kernel",
    "pre-full-kernel",
    "no FUSE daemon",
    "blocked",
    "fail closed",
    "raw-store inventory",
    "raw-store bypass",
    "transform authority",
    "mounted compression policy",
    "helper/library tier",
    "not an end-to-end mounted filesystem",
];

const APP_INDEX_LIMITATION_MARKERS: &[&str] = &[
    "checked package-role authority",
    "mirrors the current app-root inventory only for navigation",
    "operator entrypoint for CLI/UAPI work; TFR-011 and TFR-019 remain open",
    "non-production Local Filesystem exercise only",
    "cluster authority remains TFR-017",
    "non-production Local Object Store exercise only",
    "not production-readiness claims",
];

const CRATE_INDEX_LIMITATION_MARKERS: &[&str] = &[
    "current package-role authority is `docs/workspace-package-classification.md`",
    "validates that authority against Cargo metadata",
    "manifest discovery",
    "root `workspace.exclude` list",
    "only a navigation aid, not a second package table",
    "Capability wording for crates remains behind implementation reality",
    "`docs/CLAIMS_GATE_POLICY.md`",
    "`cargo run -p tidefs-xtask -- check-claims-gate`",
];

const COMMAND_AUTHORITY_TABLE_DOCS: &[&str] = &[
    "docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md",
    "docs/book/chapters/10-tidefsctl.adoc",
    "docs/security/operator-authz-boundary.md",
    "docs/CLAIMS_GATE_POLICY.md",
];

pub const CLAIM_REGISTRY_PATH: &str = "validation/claims.toml";
pub const CLAIM_REGISTRY_DOC_PATH: &str = "docs/CLAIM_REGISTRY.md";

const MODEL_CRASH_MATRIX_EVIDENCE_CLASS: &str = "model-crash-matrix";
const RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS: &str = "runtime-crash-oracle";
const RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS: &str = "runtime-namespace-crash-artifact";
const CLAIMS_GATE_REVIEW_EVIDENCE_CLASS: &str = "claims-gate-review";
const CRASH_MODEL_MATRIX_PATH: &str = "validation/artifacts/crash-oracle/model-crash-matrices.json";
const CRASH_CLAIMS_GATE_REVIEW_PATH: &str =
    "validation/artifacts/crash-oracle/claims-gate-review.toml";
const CRASH_MODEL_EVIDENCE_SOURCE: &str = "tidefs-crash-oracle";
const CRASH_MODEL_EVIDENCE_SCOPE: &str = "model-only";
const CRASH_MODEL_EVIDENCE_SCOPE_WORDING: &str =
    "bounded model-only crash matrix; no local runtime crash injection";
const CRASH_RUNTIME_CLAIM_BOUNDARY_WORDING: &str =
    "model crash matrices remain model-only; local runtime crash claims require matching runtime artifacts before validation";
const CRASH_MODEL_GENERATOR_PREFIX: &str = "tidefs-crash-oracle-rust-v";
const CRASH_MODEL_BACKEND: &str = "tidefs-model-core";
const CRASH_WRITE_FSYNC_MATRIX_ID: &str = "model.write_fsync_crash_matrix.v1";
const CRASH_RENAME_MATRIX_ID: &str = "model.rename_atomic_crash_matrix.v1";
const STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID: &str = "storage.write_fsync.crash_safety.v1";
const NAMESPACE_RENAME_CRASH_CLAIM_ID: &str = "namespace.rename.atomicity.v1";
const LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID: &str = "local.vfs.write_fsync_crash.v1";
const LOCAL_VFS_RENAME_CRASH_CLAIM_ID: &str = "local.vfs.rename_atomic_crash.v1";
const CRASH_CLAIMS_GATE_REVIEW_SOURCE: &str = "claims-gate";
const CRASH_CLAIMS_GATE_REVIEW_SCOPE: &str = "model-runtime-boundary-review";
const CRASH_CLAIMS_GATE_REVIEW_ISSUE: u64 = 329;

const CRASH_CLAIM_IDS: &[&str] = &[
    STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
    NAMESPACE_RENAME_CRASH_CLAIM_ID,
    LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID,
    LOCAL_VFS_RENAME_CRASH_CLAIM_ID,
];

const REQUIRED_INITIAL_CLAIMS: &[&str] = &[
    STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
    NAMESPACE_RENAME_CRASH_CLAIM_ID,
    "scheduler.dirty_debt.no_hidden.v1",
    "scrub.foreground_read.protected.v1",
    "perf.local.no_unbounded_dirty_debt.v1",
    "perf.local.foreground_read_not_blocked_by_scrub.v1",
    "offload.ready.non_authoritative.v1",
    "ublk.qid_tag.exactly_once_completion.v1",
    "kernel.teardown.no_work_after.v1",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandSurfaceFact {
    path: String,
    class: String,
    routing: String,
    summary: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimRegistry {
    registry_version: u32,
    generated_doc_path: String,
    claims: Vec<ClaimRecord>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimRecord {
    id: String,
    status: ClaimStatus,
    scope: String,
    required_evidence_classes: Vec<String>,
    #[serde(default)]
    evidence_requirements: Vec<ClaimEvidenceRequirement>,
    blockers: Vec<String>,
    generated_doc: String,
    #[serde(default)]
    evidence_artifacts: Vec<ClaimEvidenceArtifact>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimEvidenceRequirement {
    class: String,
    path: String,
    validation_tier: ValidationTier,
    #[serde(default)]
    manifest_path: Option<String>,
    #[serde(default)]
    blocking_issues: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ClaimEvidenceArtifact {
    class: String,
    path: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ClaimStatus {
    Planned,
    Blocked,
    Validated,
    Invalid,
}

impl ClaimStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Blocked => "blocked",
            Self::Validated => "validated",
            Self::Invalid => "invalid",
        }
    }

    const fn is_validated(self) -> bool {
        matches!(self, Self::Validated)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimValidationFormat {
    Summary,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimReceiptStatus {
    Pass,
    Blocked,
    Fail,
}

impl ClaimReceiptStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Blocked => "BLOCKED",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EvidenceClassStatus {
    Present,
    Blocked,
    Missing,
    Malformed,
    Stale,
}

impl EvidenceClassStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "PRESENT",
            Self::Blocked => "BLOCKED",
            Self::Missing => "MISSING",
            Self::Malformed => "MALFORMED",
            Self::Stale => "STALE",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ClaimValidationReceipt {
    claim_id: String,
    status: ClaimReceiptStatus,
    registry_status: String,
    scope: String,
    required_evidence: Vec<ClaimEvidenceClassReceipt>,
    blockers: Vec<String>,
    generated_doc: String,
}

#[derive(Clone, Debug, Serialize)]
struct ClaimEvidenceClassReceipt {
    class: String,
    status: EvidenceClassStatus,
    artifact_path: String,
    validation_tier: String,
    blocking_issues: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    residual_risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_scope: Option<String>,
    details: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CrashOracleModelReport {
    report_version: u64,
    generated_by: String,
    evidence_scope: String,
    runtime_claim_boundary: String,
    matrices: Vec<CrashOracleModelMatrix>,
    runtime_claims: Vec<RuntimeCrashClaimStatus>,
}

#[derive(Debug, Deserialize)]
struct CrashOracleModelMatrix {
    id: String,
    claim_ids: Vec<String>,
    backend: String,
    cases: Vec<CrashOracleModelCase>,
}

#[derive(Debug, Deserialize)]
struct CrashOracleModelCase {
    id: String,
    classification: String,
    recovered_state_diffs: Vec<serde_json::Value>,
    minimized_trace: Option<CrashOracleModelTrace>,
}

#[derive(Debug, Deserialize)]
struct CrashOracleModelTrace {
    operations: Vec<CrashOracleModelTraceOp>,
}

#[derive(Debug, Deserialize)]
struct CrashOracleModelTraceOp {
    op: String,
}

#[derive(Debug, Deserialize)]
struct RuntimeCrashClaimStatus {
    claim_id: String,
    status: String,
    classification: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct CrashClaimsGateReviewArtifact {
    artifact_version: u32,
    evidence_class: String,
    source: String,
    scope: String,
    issue: u64,
    model_artifact: String,
    model_evidence_class: String,
    model_evidence_scope: String,
    runtime_claim_boundary: String,
    reviewed_claim_ids: Vec<String>,
    missing_runtime_evidence_classes: Vec<String>,
    runtime_evidence_status: String,
    decision: String,
    boundary_review: Vec<String>,
    non_claims: Vec<String>,
}

#[derive(Debug)]
pub struct ClaimsGateCheckError {
    missing: Vec<String>,
}

impl fmt::Display for ClaimsGateCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "claims gate check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClaimValidationError {
    failures: Vec<String>,
}

impl fmt::Display for ClaimValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}: claim validation failed closed",
            self.outcome_label()
        )?;
        for item in &self.failures {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

impl ClaimValidationError {
    fn outcome_label(&self) -> &'static str {
        if self
            .failures
            .iter()
            .any(|failure| claim_state_failure_is_blocked(failure))
        {
            "BLOCKED"
        } else {
            "FAIL"
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimGateRuleTopic {
    ScannedPublishingSurfaces,
    ForbiddenCurrentCapabilityClaims,
    RequiredLimitationMarkers,
    WorkStateAuthority,
    UnreleasedAuthority,
    EvidenceBeforeEscalation,
    MountedTransformAuthority,
    OperatorCommandClassification,
    ClaimRegistryAuthority,
}

impl ClaimGateRuleTopic {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ScannedPublishingSurfaces => "claims_gate.scanned_publishing_surfaces",
            Self::ForbiddenCurrentCapabilityClaims => {
                "claims_gate.forbidden_current_capability_claims"
            }
            Self::RequiredLimitationMarkers => "claims_gate.required_limitation_markers",
            Self::WorkStateAuthority => "claims_gate.work_state_authority",
            Self::UnreleasedAuthority => "claims_gate.unreleased_authority",
            Self::EvidenceBeforeEscalation => "claims_gate.evidence_before_escalation",
            Self::MountedTransformAuthority => "claims_gate.mounted_transform_authority",
            Self::OperatorCommandClassification => "claims_gate.operator_command_classification",
            Self::ClaimRegistryAuthority => "claims_gate.claim_registry_authority",
        }
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::ScannedPublishingSurfaces => "scanned publishing surfaces",
            Self::ForbiddenCurrentCapabilityClaims => "forbidden current capability claims",
            Self::RequiredLimitationMarkers => "required limitation markers",
            Self::WorkStateAuthority => "GitHub work-state authority",
            Self::UnreleasedAuthority => "unreleased authority boundary",
            Self::EvidenceBeforeEscalation => "proof before stronger claims",
            Self::MountedTransformAuthority => "mounted transform authority",
            Self::OperatorCommandClassification => "operator command classification",
            Self::ClaimRegistryAuthority => "claim registry authority",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimGateRule {
    pub topic: ClaimGateRuleTopic,
    pub rule: &'static str,
}

pub const CLAIMS_GATE_RULES: &[ClaimGateRule] = &[
    ClaimGateRule {
        topic: ClaimGateRuleTopic::ScannedPublishingSurfaces,
        rule: "The gate scans README, current policy docs, preview handoff docs, the review register, and whole-repo review docs as user-facing publishing surfaces.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::ForbiddenCurrentCapabilityClaims,
        rule: "Current OpenZFS/Ceph successor, production-ready, POSIX-complete, distributed-storage, kernelspace-ready, and RDMA data-path claims are rejected unless the line clearly says the claim is not true yet, prohibited, future, or aspirational.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::RequiredLimitationMarkers,
        rule: "README and current preview docs must preserve explicit limitation markers so readers see prototype status and missing proof before capability summaries.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::WorkStateAuthority,
        rule: "GitHub issue and pull request state, not repo-local task, checklist, roadmap, queue, or ledger files, is the foreground Codex work-state authority.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::UnreleasedAuthority,
        rule: "Because TideFS has not had a public release, old internal TideFS paths must not be presented as product compatibility, migration, downgrade, or fallback promises unless a tracked issue names a real external boundary or operator-owned data set.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::EvidenceBeforeEscalation,
        rule: "Any stronger claim requires a tracked GitHub issue, recorded proof, and an update to this gate before the wording can become present-tense product capability.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::MountedTransformAuthority,
        rule: "Mounted device-level compression and mounted device-level encryption claims are blocked until the TFR-006 raw-store inventory records no blocked production paths; lower object-store wrappers are helper/library tier, not end-to-end mounted filesystem support.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::OperatorCommandClassification,
        rule: "tidefsctl command classification and admission must keep public operator commands, userspace harnesses, diagnostics, prototypes, development exercises, and removed surfaces in one checked registry table; cluster placement/heal exercises and cluster pool prototypes are not final distributed operator UAPI.",
    },
    ClaimGateRule {
        topic: ClaimGateRuleTopic::ClaimRegistryAuthority,
        rule: "validation/claims.toml is the source of truth for stable claim ids, status, scope, required evidence classes, blockers, and generated claim text; docs/CLAIM_REGISTRY.md must match registry-derived output exactly.",
    },
];

pub const fn claims_gate_rules() -> &'static [ClaimGateRule] {
    CLAIMS_GATE_RULES
}

pub fn check_current_workspace() -> Result<(), ClaimsGateCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClaimsGateCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_source_bound_claim_rules(&mut missing);

    // Cluster pool scaffolding gate: the cluster pool CLI and orchestrator
    // still have open TFR-017 authority limits even where cluster pool create
    // dispatches through live transport.
    check_source_markers(
        &root,
        "apps/tidefsctl/src/commands/cluster.rs",
        &[
            "dispatches per-node create requests through",
            "Review debt TFR-017",
            "import, lease ownership, and clustered mount remain",
            "POOLCLUSTER tracker work (#6605-#6610)",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-cluster/src/pool_orchestrator.rs",
        &[
            "caller-supplied [`PoolTransport`]",
            "does not own membership, transport authentication",
            "final distributed operator UAPI",
            "TFR-017 remains open",
            "crate-local boundary",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefsctl/src/commands/classification.rs",
        &[
            "tidefsctl-command-classification-v1",
            "COMMAND_SURFACES",
            "public-operator",
            "userspace-harness",
            "operator-diagnostic",
            "prototype",
            "development-diagnostic",
            "removed-or-unsupported",
            "cluster placement exercise",
            "cluster heal exercise",
            "not final distributed operator UAPI",
            "pool list",
            "device rebuild",
            "live-owner-or-offline-input",
        ],
        &mut missing,
    );

    for rel in CLAIMS_GATE_SCANNED_DOCS
        .iter()
        .copied()
        .chain(["xtask/tidefs-xtask/src/claims.rs", CLAIM_REGISTRY_PATH])
    {
        check_required_file(&root, rel, &mut missing);
    }

    check_claim_registry_docs(&root, &mut missing);
    check_command_authority_docs(&root, &mut missing);

    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/claims.rs",
        &[
            "CLAIMS_GATE_POLICY_SPEC",
            "CLAIMS_GATE_REQUIRED_COMMAND",
            "CLAIMS_GATE_SCANNED_DOCS",
            "CLAIMS_GATE_SENSITIVE_PATTERNS",
            "CLAIM_REGISTRY_PATH",
            "CLAIM_REGISTRY_DOC_PATH",
            "ClaimGateRuleTopic",
            "ClaimGateRule",
            "CLAIMS_GATE_RULES",
            "validate_claim_current_workspace",
            "render_claim_registry_doc",
            "GitHub issue and pull request state",
            "unreleased authority boundary",
            "mounted transform authority",
            "operator command classification",
            "validation/claims.toml",
            "command_authority_table_from_workspace",
            "command_admission",
            "MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY",
            "claims_gate_policy_covers_current_claim_boundaries",
            "claim_registry_doc_matches_registry",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/CLAIMS_GATE_POLICY.md",
        &[
            "tracked GitHub issue",
            "validation/claims.toml",
            "docs/CLAIM_REGISTRY.md",
            "validate-claim",
            "apps/README.md",
            "crates/README.md",
            "docs/workspace-package-classification.md",
            "OpenZFS/Ceph successor claim",
            "production-ready",
            "POSIX-complete",
            "check-claims-gate",
            "Proof Before Stronger Claims",
            "explicit limitation framing",
            "Unreleased Authority Boundary",
            "Mounted Transform Authority",
            "raw-store inventory",
            "Operator Command Classification",
            "tidefsctl-command-classification-v1",
            "apps/tidefsctl/src/commands/authz.rs",
            "command_admission",
            "cluster placement exercise",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/README.md",
        APP_INDEX_LIMITATION_MARKERS,
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/README.md",
        CRATE_INDEX_LIMITATION_MARKERS,
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md",
        &[
            "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes",
            "reclaim identity",
            "mounted filesystem open with device compression or encryption",
            "must fail closed",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/UNRELEASED_AUTHORITY_POLICY.md",
        &[
            "TideFS has not had a public release",
            "Do not add or preserve legacy",
            "operator-owned data set",
            "current authority",
            "retired pre-release path",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "README.md",
        &[
            "does not currently fulfill",
            "pre-alpha",
            "check-claims-gate",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md",
        &[
            "historical tracker item 202",
            "vfs_boundary_mirror",
            "production Linux ioctl, statx, or ublk ABI",
            "not proof that TideFS is kernelspace-ready",
            "tidefsctl-command-classification-v1",
            "apps/tidefsctl/src/commands/classification.rs",
            "public-operator",
            "userspace-harness",
            "operator-diagnostic",
            "prototype",
            "development-diagnostic",
            "removed-or-unsupported",
            "cluster placement exercise",
            "cluster heal exercise",
            "not final distributed operator UAPI",
            "pool list",
            "device rebuild",
            "pool integrity-check --backing-dir",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_USER_MANUAL.md",
        &[
            "does not currently fulfill",
            "not production-ready",
            "check-claims-gate",
        ],
        &mut missing,
    );

    scan_public_claim_surfaces(&root, &mut missing);

    if missing.is_empty() {
        println!(
            "claims gate ok: {} publishing docs scanned and overclaims rejected",
            CLAIMS_GATE_SCANNED_DOCS.len()
        );
        Ok(())
    } else {
        Err(ClaimsGateCheckError { missing })
    }
}

fn check_source_bound_claim_rules(missing: &mut Vec<String>) {
    if !CLAIMS_GATE_POLICY_SPEC.contains("matching proof") {
        missing.push("claims gate policy spec does not mention matching proof".to_string());
    }
    if !CLAIMS_GATE_REQUIRED_COMMAND.contains("check-claims-gate") {
        missing.push("claims gate required command does not name check-claims-gate".to_string());
    }

    let rules = claims_gate_rules();
    for topic in [
        ClaimGateRuleTopic::ScannedPublishingSurfaces,
        ClaimGateRuleTopic::ForbiddenCurrentCapabilityClaims,
        ClaimGateRuleTopic::RequiredLimitationMarkers,
        ClaimGateRuleTopic::WorkStateAuthority,
        ClaimGateRuleTopic::UnreleasedAuthority,
        ClaimGateRuleTopic::EvidenceBeforeEscalation,
        ClaimGateRuleTopic::MountedTransformAuthority,
        ClaimGateRuleTopic::OperatorCommandClassification,
        ClaimGateRuleTopic::ClaimRegistryAuthority,
    ] {
        if !rules.iter().any(|rule| rule.topic == topic) {
            missing.push(format!(
                "claims gate rules do not include {}",
                topic.human_name()
            ));
        }
    }
    for rule in rules {
        if rule.topic.stable_id().is_empty()
            || rule.topic.human_name().is_empty()
            || rule.rule.is_empty()
        {
            missing.push(
                "claims gate rule has an empty implementation-tracked non-release field"
                    .to_string(),
            );
        }
    }
}

pub fn validate_claim_current_workspace(
    id: &str,
    format: ClaimValidationFormat,
) -> Result<ClaimReceiptStatus, ClaimValidationError> {
    let root = find_workspace_root().ok_or_else(|| ClaimValidationError {
        failures: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    if id.trim().is_empty() {
        return Err(ClaimValidationError {
            failures: vec!["claim id must not be empty".to_string()],
        });
    }

    let (registry, registry_modified) =
        load_claim_registry(&root).map_err(|failure| ClaimValidationError {
            failures: vec![failure],
        })?;
    let mut failures = validate_claim_registry(&registry);
    let claim = registry.claims.iter().find(|claim| claim.id == id);
    if claim.is_none() {
        failures.push(format!(
            "claim `{id}` is not registered in `{CLAIM_REGISTRY_PATH}`"
        ));
    }
    if !failures.is_empty() {
        return Err(ClaimValidationError { failures });
    }

    let claim = claim.expect("claim presence checked above");
    let receipt = build_claim_validation_receipt(&root, registry_modified, claim);
    render_claim_validation_receipt(&receipt, format).map_err(|failure| ClaimValidationError {
        failures: vec![failure],
    })?;
    Ok(receipt.status)
}

fn render_claim_validation_receipt(
    receipt: &ClaimValidationReceipt,
    format: ClaimValidationFormat,
) -> Result<(), String> {
    match format {
        ClaimValidationFormat::Summary => {
            print!("{}", render_claim_validation_summary(receipt));
            Ok(())
        }
        ClaimValidationFormat::Json => {
            let text = serde_json::to_string_pretty(receipt)
                .map_err(|err| format!("serialize claim validation receipt: {err}"))?;
            println!("{text}");
            Ok(())
        }
    }
}

fn render_claim_validation_summary(receipt: &ClaimValidationReceipt) -> String {
    let mut out = String::new();
    out.push_str(&format!("claim_id: {}\n", receipt.claim_id));
    out.push_str(&format!("status: {}\n", receipt.status.as_str()));
    out.push_str(&format!("registry_status: {}\n", receipt.registry_status));
    out.push_str(&format!("scope: {}\n", receipt.scope));
    out.push_str("required_evidence:\n");
    for evidence in &receipt.required_evidence {
        out.push_str(&format!("  - class: {}\n", evidence.class));
        out.push_str(&format!("    status: {}\n", evidence.status.as_str()));
        out.push_str(&format!("    artifact_path: {}\n", evidence.artifact_path));
        out.push_str(&format!(
            "    validation_tier: {}\n",
            evidence.validation_tier
        ));
        if let Some(manifest_path) = &evidence.manifest_path {
            out.push_str(&format!("    manifest_path: {manifest_path}\n"));
        }
        if let Some(content_digest) = &evidence.content_digest {
            out.push_str(&format!("    content_digest: {content_digest}\n"));
        }
        if let Some(run_id) = &evidence.run_id {
            out.push_str(&format!("    run_id: {run_id}\n"));
        }
        if let Some(source_ref) = &evidence.source_ref {
            out.push_str(&format!("    source_ref: {source_ref}\n"));
        }
        if let Some(outcome) = &evidence.outcome {
            out.push_str(&format!("    outcome: {outcome}\n"));
        }
        if let Some(residual_risk) = &evidence.residual_risk {
            out.push_str(&format!("    residual_risk: {residual_risk}\n"));
        }
        if let Some(source) = &evidence.source {
            out.push_str(&format!("    source: {source}\n"));
        }
        if let Some(scope) = &evidence.evidence_scope {
            out.push_str(&format!("    evidence_scope: {scope}\n"));
        }
        let issues = if evidence.blocking_issues.is_empty() {
            "-".to_string()
        } else {
            evidence.blocking_issues.join(", ")
        };
        out.push_str(&format!("    blocking_issues: {issues}\n"));
        if !evidence.details.is_empty() {
            out.push_str("    details:\n");
            for detail in &evidence.details {
                out.push_str(&format!("      - {detail}\n"));
            }
        }
    }
    if !receipt.blockers.is_empty() {
        out.push_str("blockers:\n");
        for blocker in &receipt.blockers {
            out.push_str(&format!("  - {blocker}\n"));
        }
    }
    out.push_str(&format!("generated_doc: {}\n", receipt.generated_doc));
    out
}

fn build_claim_validation_receipt(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
) -> ClaimValidationReceipt {
    let enforce_freshness = claim.status.is_validated();
    let required_evidence = claim
        .required_evidence_classes
        .iter()
        .map(|class| {
            build_claim_evidence_class_receipt(
                root,
                registry_modified,
                claim,
                class,
                enforce_freshness,
            )
        })
        .collect::<Vec<_>>();
    let has_evidence_gap = required_evidence.iter().any(|evidence| {
        evidence.status != EvidenceClassStatus::Present || !evidence.blocking_issues.is_empty()
    });
    let status = match claim.status {
        ClaimStatus::Validated if !has_evidence_gap => ClaimReceiptStatus::Pass,
        ClaimStatus::Validated => ClaimReceiptStatus::Fail,
        ClaimStatus::Invalid => ClaimReceiptStatus::Fail,
        ClaimStatus::Planned | ClaimStatus::Blocked => ClaimReceiptStatus::Blocked,
    };

    ClaimValidationReceipt {
        claim_id: claim.id.clone(),
        status,
        registry_status: claim.status.as_str().to_string(),
        scope: claim.scope.clone(),
        required_evidence,
        blockers: claim.blockers.clone(),
        generated_doc: claim.generated_doc.clone(),
    }
}

fn build_claim_evidence_class_receipt(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
    class: &str,
    enforce_freshness: bool,
) -> ClaimEvidenceClassReceipt {
    let requirement = claim
        .evidence_requirements
        .iter()
        .find(|requirement| requirement.class == class);
    let matching = claim
        .evidence_artifacts
        .iter()
        .filter(|artifact| artifact.class == class)
        .collect::<Vec<_>>();
    let artifact_path = requirement
        .map(|requirement| requirement.path.clone())
        .or_else(|| matching.first().map(|artifact| artifact.path.clone()))
        .unwrap_or_default();
    let validation_tier = requirement
        .map(|requirement| requirement.validation_tier.label().to_string())
        .unwrap_or_else(|| inferred_validation_tier(class).label().to_string());
    let blocking_issues = requirement
        .map(|requirement| requirement.blocking_issues.clone())
        .unwrap_or_else(|| issue_refs_from_blockers(&claim.blockers));

    if let Some(requirement) = requirement {
        if requirement.manifest_path.is_some() {
            let manifest_details = validate_evidence_manifest_for_requirement(
                root,
                registry_modified,
                claim,
                requirement,
                enforce_freshness,
            );
            let mut all_blocking_issues = blocking_issues;
            all_blocking_issues.extend(manifest_details.blocking_issues);
            all_blocking_issues.sort();
            all_blocking_issues.dedup();
            return ClaimEvidenceClassReceipt {
                class: class.to_string(),
                status: manifest_details.status,
                artifact_path: manifest_details
                    .artifact_path
                    .unwrap_or_else(|| requirement.path.clone()),
                validation_tier,
                blocking_issues: all_blocking_issues,
                manifest_path: requirement.manifest_path.clone(),
                content_digest: manifest_details.content_digest,
                run_id: manifest_details.run_id,
                source_ref: manifest_details.source_ref,
                outcome: manifest_details.outcome,
                residual_risk: manifest_details.residual_risk,
                source: manifest_details.source,
                evidence_scope: manifest_details.evidence_scope,
                details: manifest_details.details,
            };
        }
    }

    if matching.is_empty() {
        return ClaimEvidenceClassReceipt {
            class: class.to_string(),
            status: EvidenceClassStatus::Missing,
            artifact_path,
            validation_tier,
            blocking_issues,
            manifest_path: None,
            content_digest: None,
            run_id: None,
            source_ref: None,
            outcome: None,
            residual_risk: None,
            source: None,
            evidence_scope: None,
            details: vec![format!(
                "no evidence_artifacts entry registers class `{class}` for claim `{}`",
                claim.id
            )],
        };
    }

    let mut details = Vec::new();
    let mut status = EvidenceClassStatus::Present;
    for artifact in matching {
        let artifact_details = validate_evidence_artifact_for_receipt(
            root,
            registry_modified,
            claim,
            artifact,
            enforce_freshness,
        );
        status = worse_evidence_status(status, artifact_details.status);
        details.extend(artifact_details.details);
    }

    ClaimEvidenceClassReceipt {
        class: class.to_string(),
        status,
        artifact_path,
        validation_tier,
        blocking_issues,
        manifest_path: None,
        content_digest: None,
        run_id: None,
        source_ref: None,
        outcome: None,
        residual_risk: None,
        source: None,
        evidence_scope: None,
        details,
    }
}

struct EvidenceManifestReceiptDetails {
    status: EvidenceClassStatus,
    artifact_path: Option<String>,
    content_digest: Option<String>,
    run_id: Option<String>,
    source_ref: Option<String>,
    outcome: Option<String>,
    residual_risk: Option<String>,
    source: Option<String>,
    evidence_scope: Option<String>,
    blocking_issues: Vec<String>,
    details: Vec<String>,
}

fn validate_evidence_manifest_for_requirement(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
    requirement: &ClaimEvidenceRequirement,
    enforce_freshness: bool,
) -> EvidenceManifestReceiptDetails {
    let Some(manifest_path) = requirement.manifest_path.as_deref() else {
        return EvidenceManifestReceiptDetails::empty(EvidenceClassStatus::Missing);
    };
    let rel = match workspace_relative_str_path(claim, "evidence manifest", manifest_path) {
        Ok(rel) => rel,
        Err(err) => {
            return EvidenceManifestReceiptDetails {
                details: vec![err],
                ..EvidenceManifestReceiptDetails::empty(EvidenceClassStatus::Missing)
            };
        }
    };

    let full_path = root.join(&rel);
    let metadata = match fs::metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return EvidenceManifestReceiptDetails {
                details: vec![format!(
                    "claim `{}` missing evidence manifest `{manifest_path}` for class `{}`: {err}",
                    claim.id, requirement.class
                )],
                ..EvidenceManifestReceiptDetails::empty(EvidenceClassStatus::Missing)
            };
        }
    };

    let manifest = match load_evidence_artifact_manifest_json_path(&full_path) {
        Ok(manifest) => manifest,
        Err(err) => {
            return EvidenceManifestReceiptDetails {
                details: vec![format!(
                    "claim `{}` evidence manifest `{manifest_path}` for class `{}` is malformed or unsupported: {err}",
                    claim.id, requirement.class
                )],
                ..EvidenceManifestReceiptDetails::empty(EvidenceClassStatus::Malformed)
            };
        }
    };

    let mut details = Vec::new();
    let mut status = EvidenceClassStatus::Present;
    if enforce_freshness && !committed_evidence_tree_is_current(root, &rel) {
        match metadata.modified() {
            Ok(modified) if modified < registry_modified => {
                status = worse_evidence_status(status, EvidenceClassStatus::Stale);
                details.push(format!(
                    "claim `{}` has stale evidence manifest `{manifest_path}` for class `{}`; manifest is older than `{CLAIM_REGISTRY_PATH}`",
                    claim.id, requirement.class
                ));
            }
            Ok(_) => {}
            Err(err) => {
                status = worse_evidence_status(status, EvidenceClassStatus::Stale);
                details.push(format!(
                    "claim `{}` could not read mtime for evidence manifest `{manifest_path}`: {err}",
                    claim.id
                ));
            }
        }
    }

    let artifact_rel = match manifest.artifact_path_under(root) {
        Ok(path) => path
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| PathBuf::from(&manifest.artifact_path)),
        Err(err) => {
            status = worse_evidence_status(status, EvidenceClassStatus::Malformed);
            details.push(format!(
                "claim `{}` evidence manifest `{manifest_path}` has invalid artifact_path for class `{}`: {err}",
                claim.id, requirement.class
            ));
            PathBuf::from(&manifest.artifact_path)
        }
    };

    if let Err(err) = manifest.verify_artifact_digest(root) {
        let error_text = err.to_string();
        let digest_status = if error_text.contains("read artifact_path") {
            EvidenceClassStatus::Missing
        } else {
            EvidenceClassStatus::Stale
        };
        status = worse_evidence_status(status, digest_status);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` failed artifact digest verification for class `{}`: {err}",
            claim.id, requirement.class
        ));
    }

    if enforce_freshness && !committed_evidence_tree_is_current(root, &artifact_rel) {
        match fs::metadata(root.join(&artifact_rel)).and_then(|metadata| metadata.modified()) {
            Ok(modified) if modified < registry_modified => {
                status = worse_evidence_status(status, EvidenceClassStatus::Stale);
                details.push(format!(
                    "claim `{}` has stale evidence artifact `{}` for class `{}`; artifact is older than `{CLAIM_REGISTRY_PATH}`",
                    claim.id, manifest.artifact_path, requirement.class
                ));
            }
            Ok(_) => {}
            Err(err) => {
                status = worse_evidence_status(status, EvidenceClassStatus::Missing);
                details.push(format!(
                    "claim `{}` could not read evidence artifact `{}` for class `{}`: {err}",
                    claim.id, manifest.artifact_path, requirement.class
                ));
            }
        }
    }

    status = validate_manifest_matches_requirement(
        root,
        claim,
        requirement,
        manifest_path,
        &manifest,
        enforce_freshness,
        status,
        &mut details,
    );

    let mut blocking_issues = manifest
        .blocking_issues
        .iter()
        .map(blocking_issue_ref_label)
        .collect::<Vec<_>>();
    blocking_issues.sort();
    blocking_issues.dedup();

    EvidenceManifestReceiptDetails {
        status,
        artifact_path: Some(manifest.artifact_path),
        content_digest: Some(manifest.content_digest),
        run_id: Some(manifest.run_id),
        source_ref: Some(manifest.source_ref),
        outcome: Some(manifest.outcome.label().to_string()),
        residual_risk: Some(manifest.residual_risk),
        source: Some(manifest.source),
        evidence_scope: Some(manifest.scope),
        blocking_issues,
        details,
    }
}

impl EvidenceManifestReceiptDetails {
    fn empty(status: EvidenceClassStatus) -> Self {
        Self {
            status,
            artifact_path: None,
            content_digest: None,
            run_id: None,
            source_ref: None,
            outcome: None,
            residual_risk: None,
            source: None,
            evidence_scope: None,
            blocking_issues: Vec::new(),
            details: Vec::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_manifest_matches_requirement(
    root: &Path,
    claim: &ClaimRecord,
    requirement: &ClaimEvidenceRequirement,
    manifest_path: &str,
    manifest: &EvidenceArtifactManifest,
    enforce_freshness: bool,
    mut status: EvidenceClassStatus,
    details: &mut Vec<String>,
) -> EvidenceClassStatus {
    if manifest.claim_id != claim.id {
        status = worse_evidence_status(status, EvidenceClassStatus::Malformed);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` names claim_id `{}`, expected `{}`",
            claim.id, manifest.claim_id, claim.id
        ));
    }
    if manifest.evidence_class != requirement.class {
        status = worse_evidence_status(status, EvidenceClassStatus::Malformed);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` names evidence_class `{}`, expected `{}`",
            claim.id, manifest.evidence_class, requirement.class
        ));
    }
    if manifest.validation_tier != requirement.validation_tier {
        status = worse_evidence_status(status, EvidenceClassStatus::Malformed);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` names validation_tier `{}`, expected `{}`",
            claim.id, manifest.validation_tier, requirement.validation_tier
        ));
    }
    if manifest.artifact_path != requirement.path {
        status = worse_evidence_status(status, EvidenceClassStatus::Malformed);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` names artifact_path `{}`, expected `{}`",
            claim.id, manifest.artifact_path, requirement.path
        ));
    }
    if manifest.outcome != ValidationStatus::Pass {
        status = worse_evidence_status(status, EvidenceClassStatus::Blocked);
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` outcome is `{}`, expected `PASS` for claim closure",
            claim.id,
            manifest.outcome.label()
        ));
    }
    if !manifest.blocking_issues.is_empty() {
        status = worse_evidence_status(status, EvidenceClassStatus::Blocked);
        let issues = manifest
            .blocking_issues
            .iter()
            .map(blocking_issue_ref_label)
            .collect::<Vec<_>>()
            .join(", ");
        details.push(format!(
            "claim `{}` evidence manifest `{manifest_path}` names unresolved blocking issues: {issues}",
            claim.id
        ));
    }
    if !requirement.blocking_issues.is_empty() {
        status = worse_evidence_status(status, EvidenceClassStatus::Blocked);
        details.push(format!(
            "claim `{}` evidence requirement for class `{}` names unresolved blocking issues: {}",
            claim.id,
            requirement.class,
            requirement.blocking_issues.join(", ")
        ));
    }
    if enforce_freshness && is_full_hex_sha(&manifest.source_ref) {
        if let Some(head) = current_git_head(root) {
            if !manifest.source_ref.eq_ignore_ascii_case(&head) {
                status = worse_evidence_status(status, EvidenceClassStatus::Stale);
                details.push(format!(
                    "claim `{}` evidence manifest `{manifest_path}` source_ref `{}` does not match current HEAD `{head}`",
                    claim.id, manifest.source_ref
                ));
            }
        }
    }

    status
}

fn worse_evidence_status(
    current: EvidenceClassStatus,
    next: EvidenceClassStatus,
) -> EvidenceClassStatus {
    if evidence_status_rank(next) > evidence_status_rank(current) {
        next
    } else {
        current
    }
}

const fn evidence_status_rank(status: EvidenceClassStatus) -> u8 {
    match status {
        EvidenceClassStatus::Present => 0,
        EvidenceClassStatus::Blocked => 1,
        EvidenceClassStatus::Stale => 2,
        EvidenceClassStatus::Missing => 3,
        EvidenceClassStatus::Malformed => 4,
    }
}

fn blocking_issue_ref_label(issue: &BlockingIssueRef) -> String {
    match issue.repo.as_deref() {
        Some("tidefs/tidefs") | None => format!("#{}", issue.number),
        Some(repo) => format!("{repo}#{}", issue.number),
    }
}

fn current_git_head(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let head = String::from_utf8(output.stdout).ok()?;
    let head = head.trim();
    if is_full_hex_sha(head) {
        Some(head.to_string())
    } else {
        None
    }
}

fn is_full_hex_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct EvidenceArtifactReceiptDetails {
    status: EvidenceClassStatus,
    details: Vec<String>,
}

fn validate_evidence_artifact_for_receipt(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
    enforce_freshness: bool,
) -> EvidenceArtifactReceiptDetails {
    let rel = Path::new(&artifact.path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return EvidenceArtifactReceiptDetails {
            status: EvidenceClassStatus::Missing,
            details: vec![format!(
                "claim `{}` evidence artifact `{}` must be a workspace-relative path",
                claim.id, artifact.path
            )],
        };
    }

    let artifact_path = root.join(rel);
    let metadata = match fs::metadata(&artifact_path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return EvidenceArtifactReceiptDetails {
                status: EvidenceClassStatus::Missing,
                details: vec![format!(
                    "claim `{}` missing evidence artifact `{}` for class `{}`: {err}",
                    claim.id, artifact.path, artifact.class
                )],
            };
        }
    };

    let mut details = Vec::new();
    if enforce_freshness && !committed_evidence_tree_is_current(root, rel) {
        match metadata.modified() {
            Ok(modified) if modified < registry_modified => details.push(format!(
                "claim `{}` has stale evidence artifact `{}` for class `{}`; artifact is older than `{CLAIM_REGISTRY_PATH}`",
                claim.id, artifact.path, artifact.class
            )),
            Ok(_) => {}
            Err(err) => details.push(format!(
                "claim `{}` could not read mtime for evidence artifact `{}`: {err}",
                claim.id, artifact.path
            )),
        }
    }

    details.extend(validate_claim_evidence_artifact_content(
        root, claim, artifact,
    ));
    let status = if details.is_empty() {
        EvidenceClassStatus::Present
    } else {
        EvidenceClassStatus::Stale
    };
    EvidenceArtifactReceiptDetails { status, details }
}

fn committed_evidence_tree_is_current(root: &Path, artifact_rel: &Path) -> bool {
    let Some(artifact_rel) = artifact_rel.to_str() else {
        return false;
    };
    git_path_tracked_and_clean(root, CLAIM_REGISTRY_PATH)
        && git_path_tracked_and_clean(root, artifact_rel)
}

fn git_path_tracked_and_clean(root: &Path, rel: &str) -> bool {
    let tracked = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["ls-files", "--error-unmatch", "--", rel])
        .output();
    if !matches!(tracked, Ok(output) if output.status.success()) {
        return false;
    }

    let clean_checks: &[&[&str]] = &[
        &["diff", "--quiet", "--exit-code", "HEAD", "--", rel],
        &[
            "diff",
            "--cached",
            "--quiet",
            "--exit-code",
            "HEAD",
            "--",
            rel,
        ],
    ];
    for args in clean_checks {
        let status = Command::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args.iter().copied())
            .status();
        if !matches!(status, Ok(status) if status.success()) {
            return false;
        }
    }

    true
}

fn validate_claim_evidence_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = Vec::new();
    if artifact.class == UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS {
        failures.extend(validate_runtime_ublk_completion_artifact_content(
            root, claim, artifact,
        ));
    }
    if artifact.class == UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS {
        failures.extend(
            validate_runtime_ublk_started_export_admission_artifact_content(root, claim, artifact),
        );
    }
    failures.extend(validate_crash_evidence_artifact_content(
        root, claim, artifact,
    ));
    failures
}

fn inferred_validation_tier(class: &str) -> ValidationTier {
    if class.contains("runtime") {
        ValidationTier::MountedUserspace
    } else if class.contains("gate") || class.contains("review") {
        ValidationTier::SourceModel
    } else {
        ValidationTier::CargoUnit
    }
}

fn issue_refs_from_blockers(blockers: &[String]) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for blocker in blockers {
        let bytes = blocker.as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] == b'#' {
                let start = index;
                index += 1;
                let digits_start = index;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                if index > digits_start {
                    refs.insert(blocker[start..index].to_string());
                }
            } else {
                index += 1;
            }
        }
    }
    refs.into_iter().collect()
}

fn check_claim_registry_docs(root: &Path, missing: &mut Vec<String>) {
    let (registry, registry_modified) = match load_claim_registry(root) {
        Ok(registry) => registry,
        Err(err) => {
            missing.push(err);
            return;
        }
    };

    for err in validate_claim_registry(&registry) {
        missing.push(err);
    }
    for err in validate_registered_runtime_ublk_artifacts(&root, &registry) {
        missing.push(err);
    }
    for err in validate_registered_crash_artifacts(root, registry_modified, &registry) {
        missing.push(err);
    }

    let expected = render_claim_registry_doc(&registry);
    let doc_path = root.join(CLAIM_REGISTRY_DOC_PATH);
    match fs::read_to_string(&doc_path) {
        Ok(actual) if actual == expected => {}
        Ok(_) => missing.push(format!(
            "`{CLAIM_REGISTRY_DOC_PATH}` does not match generated output from `{CLAIM_REGISTRY_PATH}`"
        )),
        Err(err) => missing.push(format!("could not read `{CLAIM_REGISTRY_DOC_PATH}`: {err}")),
    }
}

fn load_claim_registry(root: &Path) -> Result<(ClaimRegistry, SystemTime), String> {
    let path = root.join(CLAIM_REGISTRY_PATH);
    let text =
        fs::read_to_string(&path).map_err(|err| format!("read `{CLAIM_REGISTRY_PATH}`: {err}"))?;
    let modified = fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .map_err(|err| format!("read `{CLAIM_REGISTRY_PATH}` mtime: {err}"))?;
    Ok((parse_claim_registry(&text)?, modified))
}

fn parse_claim_registry(text: &str) -> Result<ClaimRegistry, String> {
    toml::from_str(text).map_err(|err| format!("parse `{CLAIM_REGISTRY_PATH}`: {err}"))
}

fn validate_claim_registry(registry: &ClaimRegistry) -> Vec<String> {
    let mut failures = Vec::new();
    if registry.registry_version != 1 {
        failures.push(format!(
            "`{CLAIM_REGISTRY_PATH}` registry_version must be 1, found {}",
            registry.registry_version
        ));
    }
    if registry.generated_doc_path != CLAIM_REGISTRY_DOC_PATH {
        failures.push(format!(
            "`{CLAIM_REGISTRY_PATH}` generated_doc_path must be `{CLAIM_REGISTRY_DOC_PATH}`"
        ));
    }
    if registry.claims.is_empty() {
        failures.push(format!(
            "`{CLAIM_REGISTRY_PATH}` does not register any claims"
        ));
    }

    let mut ids = BTreeSet::new();
    for claim in &registry.claims {
        if claim.id.trim().is_empty() {
            failures.push("claim record has an empty id".to_string());
            continue;
        }
        if !ids.insert(claim.id.clone()) {
            failures.push(format!("duplicate claim id `{}`", claim.id));
        }
        if claim.scope.trim().is_empty() {
            failures.push(format!("claim `{}` has an empty scope", claim.id));
        }
        if claim.required_evidence_classes.is_empty() {
            failures.push(format!(
                "claim `{}` has no required_evidence_classes",
                claim.id
            ));
        }
        let mut required_classes = BTreeSet::new();
        for class in &claim.required_evidence_classes {
            if class.trim().is_empty() {
                failures.push(format!("claim `{}` has an empty evidence class", claim.id));
            }
            if !required_classes.insert(class) {
                failures.push(format!(
                    "claim `{}` repeats evidence class `{class}`",
                    claim.id
                ));
            }
        }
        let mut requirement_classes = BTreeSet::new();
        for requirement in &claim.evidence_requirements {
            if requirement.class.trim().is_empty() || requirement.path.trim().is_empty() {
                failures.push(format!(
                    "claim `{}` has an evidence requirement with empty class or path",
                    claim.id
                ));
            }
            if !requirement_classes.insert(requirement.class.as_str()) {
                failures.push(format!(
                    "claim `{}` repeats evidence requirement for class `{}`",
                    claim.id, requirement.class
                ));
            }
            if !claim
                .required_evidence_classes
                .iter()
                .any(|class| class == &requirement.class)
            {
                failures.push(format!(
                    "claim `{}` evidence requirement class `{}` is not required by the claim",
                    claim.id, requirement.class
                ));
            }
            let rel = Path::new(&requirement.path);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                failures.push(format!(
                    "claim `{}` evidence requirement path `{}` must be workspace-relative",
                    claim.id, requirement.path
                ));
            }
            if let Some(manifest_path) = &requirement.manifest_path {
                let rel = Path::new(manifest_path);
                if rel.is_absolute()
                    || rel
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir))
                {
                    failures.push(format!(
                        "claim `{}` evidence requirement manifest_path `{manifest_path}` must be workspace-relative",
                        claim.id
                    ));
                }
            }
        }
        for class in &claim.required_evidence_classes {
            if !requirement_classes.contains(class.as_str()) {
                failures.push(format!(
                    "claim `{}` required evidence class `{class}` has no evidence_requirements metadata",
                    claim.id
                ));
            }
        }
        if !claim.status.is_validated() && claim.blockers.is_empty() {
            failures.push(format!(
                "claim `{}` is {} but records no blockers",
                claim.id,
                claim.status.as_str()
            ));
        }
        if claim.status.is_validated() && !claim.blockers.is_empty() {
            failures.push(format!(
                "claim `{}` is validated but still records blockers",
                claim.id
            ));
        }
        if claim.generated_doc.trim().is_empty() {
            failures.push(format!("claim `{}` has empty generated_doc", claim.id));
        }
        let generated_doc_lower = claim.generated_doc.to_ascii_lowercase();
        if !claim.status.is_validated() && !generated_doc_lower.contains(claim.status.as_str()) {
            failures.push(format!(
                "claim `{}` generated_doc must preserve {} status wording",
                claim.id,
                claim.status.as_str()
            ));
        }
        for artifact in &claim.evidence_artifacts {
            if artifact.class.trim().is_empty() || artifact.path.trim().is_empty() {
                failures.push(format!(
                    "claim `{}` has an evidence artifact with empty class or path",
                    claim.id
                ));
            }
            if !claim
                .required_evidence_classes
                .iter()
                .any(|class| class == &artifact.class)
            {
                failures.push(format!(
                    "claim `{}` evidence artifact class `{}` is not required by the claim",
                    claim.id, artifact.class
                ));
            }
        }
        validate_crash_claim_requirements(claim, &mut failures);
    }

    for required_id in REQUIRED_INITIAL_CLAIMS {
        if !ids.contains(*required_id) {
            failures.push(format!(
                "`{CLAIM_REGISTRY_PATH}` is missing required initial claim `{required_id}`"
            ));
        }
    }

    failures
}

fn validate_crash_claim_requirements(claim: &ClaimRecord, failures: &mut Vec<String>) {
    if !is_crash_claim_id(&claim.id) {
        return;
    }

    for class in [
        MODEL_CRASH_MATRIX_EVIDENCE_CLASS,
        CLAIMS_GATE_REVIEW_EVIDENCE_CLASS,
    ] {
        if !claim
            .required_evidence_classes
            .iter()
            .any(|required| required == class)
        {
            failures.push(format!(
                "crash claim `{}` must require evidence class `{class}`",
                claim.id
            ));
        }
    }

    let runtime_class = required_crash_runtime_evidence_class(&claim.id);
    if !claim
        .required_evidence_classes
        .iter()
        .any(|required| required == runtime_class)
    {
        failures.push(format!(
            "crash claim `{}` must require runtime evidence class `{runtime_class}`",
            claim.id
        ));
    }
}

fn validate_registered_runtime_ublk_artifacts(
    root: &Path,
    registry: &ClaimRegistry,
) -> Vec<String> {
    let mut failures = Vec::new();
    for claim in &registry.claims {
        for artifact in &claim.evidence_artifacts {
            if artifact.class == UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS {
                failures.extend(validate_runtime_ublk_completion_artifact_content(
                    root, claim, artifact,
                ));
            } else if artifact.class == UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS {
                failures.extend(
                    validate_runtime_ublk_started_export_admission_artifact_content(
                        root, claim, artifact,
                    ),
                );
            }
        }
    }
    failures
}

fn validate_runtime_ublk_completion_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = Vec::new();
    let rel = Path::new(&artifact.path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` must be a workspace-relative path",
            claim.id, artifact.path
        ));
        return failures;
    }

    let artifact_path = root.join(rel);
    match validate_ublk_completion_artifact_path(&artifact_path) {
        Ok(_) => {}
        Err(error) => failures.push(format!(
            "claim `{}` runtime uBLK completion artifact `{}` failed verifier: {error}",
            claim.id, artifact.path
        )),
    }
    failures
}

fn validate_runtime_ublk_started_export_admission_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = Vec::new();
    let rel = Path::new(&artifact.path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` must be a workspace-relative path",
            claim.id, artifact.path
        ));
        return failures;
    }

    let artifact_path = root.join(rel);
    match validate_ublk_started_export_admission_artifact_path(&artifact_path) {
        Ok(_) => {}
        Err(error) => failures.push(format!(
            "claim `{}` runtime uBLK started-export admission artifact `{}` failed verifier: {error}",
            claim.id, artifact.path
        )),
    }
    failures
}

fn validate_registered_crash_artifacts(
    root: &Path,
    registry_modified: SystemTime,
    registry: &ClaimRegistry,
) -> Vec<String> {
    let mut failures = Vec::new();

    for claim in &registry.claims {
        for artifact in &claim.evidence_artifacts {
            failures.extend(validate_crash_evidence_artifact_content(
                root, claim, artifact,
            ));
        }

        if is_crash_claim_id(&claim.id) && claim.status.is_validated() {
            failures.extend(validate_claim_record(root, registry_modified, claim));
        }
    }

    failures.sort();
    failures.dedup();
    failures
}

fn validate_crash_evidence_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    match artifact.class.as_str() {
        MODEL_CRASH_MATRIX_EVIDENCE_CLASS => {
            validate_model_crash_matrix_artifact_content(root, claim, artifact)
        }
        RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS | RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS => {
            validate_runtime_crash_artifact_content(root, claim, artifact)
        }
        CLAIMS_GATE_REVIEW_EVIDENCE_CLASS if is_crash_claim_id(&claim.id) => {
            validate_crash_claims_gate_review_artifact_content(root, claim, artifact)
        }
        _ => Vec::new(),
    }
}

fn validate_model_crash_matrix_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = validate_crash_artifact_source_scope(
        claim,
        artifact,
        CRASH_MODEL_EVIDENCE_SOURCE,
        CRASH_MODEL_EVIDENCE_SCOPE,
    );

    let rel = match workspace_relative_path(claim, artifact) {
        Ok(rel) => rel,
        Err(err) => {
            failures.push(err);
            return failures;
        }
    };
    let artifact_path = root.join(&rel);
    let text = match fs::read_to_string(&artifact_path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` could not be read: {err}",
                claim.id, artifact.path
            ));
            return failures;
        }
    };
    let report: CrashOracleModelReport = match serde_json::from_str(&text) {
        Ok(report) => report,
        Err(err) => {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` is malformed JSON: {err}",
                claim.id, artifact.path
            ));
            return failures;
        }
    };

    if report.report_version != 1 {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` has report_version {}, expected 1",
            claim.id, artifact.path, report.report_version
        ));
    }
    if !report
        .generated_by
        .starts_with(CRASH_MODEL_GENERATOR_PREFIX)
    {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` has unexpected generator `{}`",
            claim.id, artifact.path, report.generated_by
        ));
    }
    if report.evidence_scope != CRASH_MODEL_EVIDENCE_SCOPE_WORDING {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` must declare model-only evidence scope `{CRASH_MODEL_EVIDENCE_SCOPE_WORDING}`",
            claim.id, artifact.path
        ));
    }
    if report.runtime_claim_boundary != CRASH_RUNTIME_CLAIM_BOUNDARY_WORDING {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` must preserve runtime boundary wording `{CRASH_RUNTIME_CLAIM_BOUNDARY_WORDING}`",
            claim.id, artifact.path
        ));
    }

    validate_expected_crash_matrix(
        claim,
        artifact,
        &report,
        CRASH_WRITE_FSYNC_MATRIX_ID,
        &[
            STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
            LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID,
        ],
        &mut failures,
    );
    validate_expected_crash_matrix(
        claim,
        artifact,
        &report,
        CRASH_RENAME_MATRIX_ID,
        &[
            NAMESPACE_RENAME_CRASH_CLAIM_ID,
            LOCAL_VFS_RENAME_CRASH_CLAIM_ID,
        ],
        &mut failures,
    );

    if !report.matrices.iter().any(|matrix| {
        matrix
            .claim_ids
            .iter()
            .any(|claim_id| claim_id == &claim.id)
    }) {
        failures.push(format!(
            "claim `{}` registers crash model artifact `{}` but no matrix names that claim id",
            claim.id, artifact.path
        ));
    }

    let forbidden_cases = report
        .matrices
        .iter()
        .flat_map(|matrix| &matrix.cases)
        .filter(|case| case.classification == "forbidden")
        .collect::<Vec<_>>();
    if forbidden_cases.is_empty() {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` has no forbidden crash cases",
            claim.id, artifact.path
        ));
    }
    for case in forbidden_cases {
        if case.recovered_state_diffs.is_empty() {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` forbidden case `{}` has no recovered-state diff",
                claim.id, artifact.path, case.id
            ));
        }
        let has_crash_recovery_trace = case
            .minimized_trace
            .as_ref()
            .map(|trace| {
                trace
                    .operations
                    .iter()
                    .any(|op| op.op == "crash_recover_at")
            })
            .unwrap_or(false);
        if !has_crash_recovery_trace {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` forbidden case `{}` has no minimized crash_recover_at trace",
                claim.id, artifact.path, case.id
            ));
        }
    }

    for claim_id in [
        LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID,
        LOCAL_VFS_RENAME_CRASH_CLAIM_ID,
    ] {
        let Some(runtime_claim) = report
            .runtime_claims
            .iter()
            .find(|runtime_claim| runtime_claim.claim_id == claim_id)
        else {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` is missing runtime boundary status for `{claim_id}`",
                claim.id, artifact.path
            ));
            continue;
        };
        if runtime_claim.status != "blocked"
            || runtime_claim.classification != "unsupported-fail-closed"
            || runtime_claim.reason.trim().is_empty()
        {
            failures.push(format!(
                "claim `{}` crash model artifact `{}` runtime status for `{claim_id}` must be blocked unsupported-fail-closed with a reason",
                claim.id, artifact.path
            ));
        }
    }

    failures
}

fn validate_expected_crash_matrix(
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
    report: &CrashOracleModelReport,
    matrix_id: &str,
    expected_claim_ids: &[&str],
    failures: &mut Vec<String>,
) {
    let Some(matrix) = report.matrices.iter().find(|matrix| matrix.id == matrix_id) else {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` is missing matrix `{matrix_id}`",
            claim.id, artifact.path
        ));
        return;
    };

    if matrix.backend != CRASH_MODEL_BACKEND {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` matrix `{matrix_id}` has backend `{}`, expected `{CRASH_MODEL_BACKEND}`",
            claim.id, artifact.path, matrix.backend
        ));
    }
    if !same_string_set(&matrix.claim_ids, expected_claim_ids) {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` matrix `{matrix_id}` has claim ids {:?}, expected {:?}",
            claim.id, artifact.path, matrix.claim_ids, expected_claim_ids
        ));
    }
    if matrix.cases.is_empty() {
        failures.push(format!(
            "claim `{}` crash model artifact `{}` matrix `{matrix_id}` has no cases",
            claim.id, artifact.path
        ));
    }
}

fn validate_runtime_crash_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = validate_crash_artifact_has_source_scope(claim, artifact);
    if artifact.path == CRASH_MODEL_MATRIX_PATH {
        failures.push(format!(
            "claim `{}` runtime crash evidence class `{}` must not point at model-only crash matrix `{CRASH_MODEL_MATRIX_PATH}`",
            claim.id, artifact.class
        ));
    }
    if artifact_source_or_scope_mentions_model_only(artifact) {
        failures.push(format!(
            "claim `{}` runtime crash evidence class `{}` is registered with model-only source/scope",
            claim.id, artifact.class
        ));
    }
    if !artifact_scope_contains_runtime(artifact) {
        failures.push(format!(
            "claim `{}` runtime crash evidence class `{}` must be source-qualified with runtime scope",
            claim.id, artifact.class
        ));
    }

    match artifact_declares_model_only_scope(root, claim, artifact) {
        Ok(true) => failures.push(format!(
            "claim `{}` runtime crash evidence class `{}` points at artifact `{}` whose declared scope is model-only",
            claim.id, artifact.class, artifact.path
        )),
        Ok(false) => {}
        Err(err) => failures.push(err),
    }

    if artifact.class == LOCAL_VFS_WRITE_FSYNC_RUNTIME_CRASH_EVIDENCE_CLASS
        && claim.id == LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID
    {
        let rel = match workspace_relative_path(claim, artifact) {
            Ok(rel) => rel,
            Err(err) => {
                failures.push(err);
                return failures;
            }
        };
        let artifact_path = root.join(&rel);
        if let Err(error) = validate_local_vfs_runtime_crash_artifact_path(&artifact_path) {
            failures.push(format!(
                "claim `{}` local VFS runtime crash artifact `{}` failed verifier: {error}",
                claim.id, artifact.path
            ));
        }
    }
    if artifact.class == LOCAL_VFS_RENAME_RUNTIME_CRASH_EVIDENCE_CLASS
        && claim.id == LOCAL_VFS_RENAME_CRASH_CLAIM_ID
    {
        let rel = match workspace_relative_path(claim, artifact) {
            Ok(rel) => rel,
            Err(err) => {
                failures.push(err);
                return failures;
            }
        };
        let artifact_path = root.join(&rel);
        if let Err(error) = validate_local_vfs_rename_runtime_crash_artifact_path(&artifact_path) {
            failures.push(format!(
                "claim `{}` local VFS rename runtime crash artifact `{}` failed verifier: {error}",
                claim.id, artifact.path
            ));
        }
    }

    failures
}

fn validate_crash_claims_gate_review_artifact_content(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = validate_crash_artifact_source_scope(
        claim,
        artifact,
        CRASH_CLAIMS_GATE_REVIEW_SOURCE,
        CRASH_CLAIMS_GATE_REVIEW_SCOPE,
    );
    if artifact.path != CRASH_CLAIMS_GATE_REVIEW_PATH {
        failures.push(format!(
            "claim `{}` crash claims-gate review must use `{CRASH_CLAIMS_GATE_REVIEW_PATH}`, found `{}`",
            claim.id, artifact.path
        ));
    }

    let rel = match workspace_relative_path(claim, artifact) {
        Ok(rel) => rel,
        Err(err) => {
            failures.push(err);
            return failures;
        }
    };
    let artifact_path = root.join(&rel);
    let text = match fs::read_to_string(&artifact_path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!(
                "claim `{}` crash claims-gate review `{}` could not be read: {err}",
                claim.id, artifact.path
            ));
            return failures;
        }
    };
    let review: CrashClaimsGateReviewArtifact = match toml::from_str(&text) {
        Ok(review) => review,
        Err(err) => {
            failures.push(format!(
                "claim `{}` crash claims-gate review `{}` is malformed TOML: {err}",
                claim.id, artifact.path
            ));
            return failures;
        }
    };

    if review.artifact_version != 1 {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` has artifact_version {}, expected 1",
            claim.id, artifact.path, review.artifact_version
        ));
    }
    if review.evidence_class != CLAIMS_GATE_REVIEW_EVIDENCE_CLASS {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must declare evidence_class `{CLAIMS_GATE_REVIEW_EVIDENCE_CLASS}`",
            claim.id, artifact.path
        ));
    }
    if review.source != CRASH_CLAIMS_GATE_REVIEW_SOURCE {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must declare source `{CRASH_CLAIMS_GATE_REVIEW_SOURCE}`",
            claim.id, artifact.path
        ));
    }
    if review.scope != CRASH_CLAIMS_GATE_REVIEW_SCOPE {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must declare scope `{CRASH_CLAIMS_GATE_REVIEW_SCOPE}`",
            claim.id, artifact.path
        ));
    }
    if review.issue != CRASH_CLAIMS_GATE_REVIEW_ISSUE {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must name issue {CRASH_CLAIMS_GATE_REVIEW_ISSUE}",
            claim.id, artifact.path
        ));
    }
    if review.model_artifact != CRASH_MODEL_MATRIX_PATH
        || review.model_evidence_class != MODEL_CRASH_MATRIX_EVIDENCE_CLASS
        || review.model_evidence_scope != CRASH_MODEL_EVIDENCE_SCOPE_WORDING
        || review.runtime_claim_boundary != CRASH_RUNTIME_CLAIM_BOUNDARY_WORDING
    {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must preserve the model/runtime evidence boundary",
            claim.id, artifact.path
        ));
    }
    if !same_string_set(&review.reviewed_claim_ids, CRASH_CLAIM_IDS) {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must review exactly the crash claim ids {:?}",
            claim.id, artifact.path, CRASH_CLAIM_IDS
        ));
    }
    if !review.reviewed_claim_ids.iter().any(|id| id == &claim.id) {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` does not review this claim id",
            claim.id, artifact.path
        ));
    }
    if !same_string_set(
        &review.missing_runtime_evidence_classes,
        expected_missing_runtime_evidence_classes(),
    ) {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` has missing runtime evidence classes {:?}, expected {:?}",
            claim.id,
            artifact.path,
            review.missing_runtime_evidence_classes,
            expected_missing_runtime_evidence_classes()
        ));
    }

    let boundary_text = review.boundary_review.join("\n").to_ascii_lowercase();
    if !boundary_text.contains("model-only")
        || !boundary_text.contains("runtime")
        || !boundary_text.contains("evidence")
    {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must explicitly review the model/runtime evidence boundary",
            claim.id, artifact.path
        ));
    }

    let decision = review.decision.to_ascii_lowercase();
    let runtime_status = review.runtime_evidence_status.to_ascii_lowercase();
    if !decision.contains("fail-closed")
        || !(decision.contains("planned") || decision.contains("blocked"))
        || !(runtime_status.contains("missing") || runtime_status.contains("present"))
    {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must keep crash claims planned/blocked and fail-closed while runtime evidence is incomplete",
            claim.id, artifact.path
        ));
    }

    let non_claims = review.non_claims.join("\n").to_ascii_lowercase();
    if !non_claims.contains("local runtime crash injection")
        || !non_claims.contains("production crash safety")
    {
        failures.push(format!(
            "claim `{}` crash claims-gate review `{}` must record crash-safety non-claims",
            claim.id, artifact.path
        ));
    }

    failures
}

fn expected_missing_runtime_evidence_classes() -> &'static [&'static str] {
    &[]
}

fn validate_crash_artifact_source_scope(
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
    expected_source: &str,
    expected_scope: &str,
) -> Vec<String> {
    let mut failures = validate_crash_artifact_has_source_scope(claim, artifact);
    if artifact.source.as_deref() != Some(expected_source) {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` for class `{}` must declare source `{expected_source}`",
            claim.id, artifact.path, artifact.class
        ));
    }
    if artifact.scope.as_deref() != Some(expected_scope) {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` for class `{}` must declare scope `{expected_scope}`",
            claim.id, artifact.path, artifact.class
        ));
    }
    failures
}

fn validate_crash_artifact_has_source_scope(
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Vec<String> {
    let mut failures = Vec::new();
    if artifact
        .source
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` for class `{}` must declare source",
            claim.id, artifact.path, artifact.class
        ));
    }
    if artifact
        .scope
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        failures.push(format!(
            "claim `{}` evidence artifact `{}` for class `{}` must declare scope",
            claim.id, artifact.path, artifact.class
        ));
    }
    failures
}

fn artifact_declares_model_only_scope(
    root: &Path,
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Result<bool, String> {
    let rel = workspace_relative_path(claim, artifact)?;
    let artifact_path = root.join(&rel);
    let text = fs::read_to_string(&artifact_path).map_err(|err| {
        format!(
            "claim `{}` runtime crash evidence artifact `{}` could not be read for source/scope inspection: {err}",
            claim.id, artifact.path
        )
    })?;

    let declared_scopes = match rel.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            let value = serde_json::from_str::<serde_json::Value>(&text).map_err(|err| {
                format!(
                    "claim `{}` runtime crash evidence artifact `{}` has malformed JSON during source/scope inspection: {err}",
                    claim.id, artifact.path
                )
            })?;
            declared_source_scope_values_from_json(&value)
        }
        Some("toml") => {
            let value = toml::from_str::<toml::Value>(&text).map_err(|err| {
                format!(
                    "claim `{}` runtime crash evidence artifact `{}` has malformed TOML during source/scope inspection: {err}",
                    claim.id, artifact.path
                )
            })?;
            declared_source_scope_values_from_toml(&value)
        }
        _ => Vec::new(),
    };

    Ok(declared_scopes
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("model-only")))
}

fn declared_source_scope_values_from_json(value: &serde_json::Value) -> Vec<String> {
    ["evidence_scope", "scope", "source", "evidence_source"]
        .iter()
        .filter_map(|key| value.get(key).and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn declared_source_scope_values_from_toml(value: &toml::Value) -> Vec<String> {
    ["evidence_scope", "scope", "source", "evidence_source"]
        .iter()
        .filter_map(|key| value.get(key).and_then(toml::Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn workspace_relative_path(
    claim: &ClaimRecord,
    artifact: &ClaimEvidenceArtifact,
) -> Result<PathBuf, String> {
    workspace_relative_str_path(claim, "evidence artifact", &artifact.path)
}

fn workspace_relative_str_path(
    claim: &ClaimRecord,
    path_kind: &str,
    path: &str,
) -> Result<PathBuf, String> {
    let rel = Path::new(path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "claim `{}` {path_kind} `{path}` must be a workspace-relative path",
            claim.id
        ));
    }
    Ok(rel.to_path_buf())
}

fn artifact_source_or_scope_mentions_model_only(artifact: &ClaimEvidenceArtifact) -> bool {
    [artifact.source.as_deref(), artifact.scope.as_deref()]
        .into_iter()
        .flatten()
        .any(|value| value.to_ascii_lowercase().contains("model-only"))
}

fn artifact_scope_contains_runtime(artifact: &ClaimEvidenceArtifact) -> bool {
    artifact
        .scope
        .as_deref()
        .map(|scope| scope.to_ascii_lowercase().contains("runtime"))
        .unwrap_or(false)
}

fn same_string_set(actual: &[String], expected: &[&str]) -> bool {
    let actual = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    actual == expected
}

fn is_crash_claim_id(id: &str) -> bool {
    CRASH_CLAIM_IDS.contains(&id)
}

fn required_crash_runtime_evidence_class(claim_id: &str) -> &'static str {
    match claim_id {
        STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID | LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID => {
            RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS
        }
        NAMESPACE_RENAME_CRASH_CLAIM_ID | LOCAL_VFS_RENAME_CRASH_CLAIM_ID => {
            RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS
        }
        _ => RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS,
    }
}

fn validate_claim_record(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
) -> Vec<String> {
    if !claim.status.is_validated() {
        let mut failures = vec![format!(
            "claim `{}` is {}; generated doc: {}",
            claim.id,
            claim.status.as_str(),
            claim.generated_doc
        )];
        if !claim.blockers.is_empty() {
            failures.push(format!(
                "claim `{}` blocker(s): {}",
                claim.id,
                claim.blockers.join("; ")
            ));
        }
        failures.extend(missing_required_evidence_class_failures(claim));
        failures.extend(validate_registered_evidence_artifacts_for_claim(
            root,
            registry_modified,
            claim,
        ));
        return failures;
    }

    validate_registered_evidence_artifacts_for_claim(root, registry_modified, claim)
}

fn validate_registered_evidence_artifacts_for_claim(
    root: &Path,
    registry_modified: SystemTime,
    claim: &ClaimRecord,
) -> Vec<String> {
    let mut failures = Vec::new();
    for class in &claim.required_evidence_classes {
        let requirement = claim
            .evidence_requirements
            .iter()
            .find(|requirement| &requirement.class == class);
        if let Some(requirement) = requirement {
            if requirement.manifest_path.is_some() {
                let manifest_details = validate_evidence_manifest_for_requirement(
                    root,
                    registry_modified,
                    claim,
                    requirement,
                    true,
                );
                failures.extend(manifest_details.details);
                continue;
            }
        }

        let matching = claim
            .evidence_artifacts
            .iter()
            .filter(|artifact| &artifact.class == class)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            failures.push(format!(
                "claim `{}` is missing evidence artifact for class `{class}`",
                claim.id
            ));
            continue;
        }
        for artifact in matching {
            let rel = Path::new(&artifact.path);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                failures.push(format!(
                    "claim `{}` evidence artifact `{}` must be a workspace-relative path",
                    claim.id, artifact.path
                ));
                continue;
            }
            let artifact_path = root.join(rel);
            let metadata = match fs::metadata(&artifact_path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    failures.push(format!(
                        "claim `{}` missing evidence artifact `{}` for class `{}`: {err}",
                        claim.id, artifact.path, artifact.class
                    ));
                    continue;
                }
            };
            if !committed_evidence_tree_is_current(root, rel) {
                let modified = match metadata.modified() {
                    Ok(modified) => modified,
                    Err(err) => {
                        failures.push(format!(
                            "claim `{}` could not read mtime for evidence artifact `{}`: {err}",
                            claim.id, artifact.path
                        ));
                        continue;
                    }
                };
                if modified < registry_modified {
                    failures.push(format!(
                        "claim `{}` has stale evidence artifact `{}` for class `{}`; artifact is older than `{CLAIM_REGISTRY_PATH}`",
                        claim.id, artifact.path, artifact.class
                    ));
                }
            }
            if artifact.class == UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS {
                failures.extend(validate_runtime_ublk_completion_artifact_content(
                    root, claim, artifact,
                ));
            }
            if artifact.class == UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS {
                failures.extend(
                    validate_runtime_ublk_started_export_admission_artifact_content(
                        root, claim, artifact,
                    ),
                );
            }
            failures.extend(validate_crash_evidence_artifact_content(
                root, claim, artifact,
            ));
        }
    }
    failures
}

fn missing_required_evidence_class_failures(claim: &ClaimRecord) -> Vec<String> {
    claim
        .required_evidence_classes
        .iter()
        .filter(|class| {
            !claim
                .evidence_artifacts
                .iter()
                .any(|artifact| &artifact.class == *class)
                && !claim.evidence_requirements.iter().any(|requirement| {
                    &requirement.class == *class && requirement.manifest_path.is_some()
                })
        })
        .map(|class| {
            format!(
                "claim `{}` is missing evidence artifact for class `{class}`",
                claim.id
            )
        })
        .collect()
}

fn claim_state_failure_is_blocked(failure: &str) -> bool {
    failure.contains(" is planned") || failure.contains(" is blocked")
}

fn render_claim_registry_doc(registry: &ClaimRegistry) -> String {
    let mut out = String::new();
    out.push_str("# TideFS Claim Registry\n\n");
    out.push_str("Maturity: generated claim registry.\n\n");
    out.push_str("This file is generated from `validation/claims.toml` by `cargo run -p tidefs-xtask -- check-claims-gate`. Edit the registry, not this document.\n\n");
    out.push_str("`validate-claim <id>` prints PASS, BLOCKED, or FAIL. PASS is limited to validated claims with fresh evidence artifacts; BLOCKED exits successfully for focused validation while remaining a non-product claim, and FAIL exits nonzero.\n\n");
    out.push_str("| Claim id | Status | Scope | Required evidence | Blockers | Generated text |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for claim in &registry.claims {
        out.push_str("| `");
        out.push_str(&markdown_cell(&claim.id));
        out.push_str("` | `");
        out.push_str(claim.status.as_str());
        out.push_str("` | ");
        out.push_str(&markdown_cell(&claim.scope));
        out.push_str(" | ");
        out.push_str(&markdown_list_cell(&claim.required_evidence_classes));
        out.push_str(" | ");
        out.push_str(&markdown_list_cell(&claim.blockers));
        out.push_str(" | ");
        out.push_str(&markdown_cell(&claim.generated_doc));
        out.push_str(" |\n");
    }
    out
}

fn markdown_list_cell(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values
            .iter()
            .map(|value| markdown_cell(value))
            .collect::<Vec<_>>()
            .join("<br>")
    }
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn check_command_authority_docs(root: &Path, missing: &mut Vec<String>) {
    let table = match command_authority_table_from_workspace(root) {
        Ok(table) => table,
        Err(err) => {
            missing.push(err);
            return;
        }
    };

    for rel in COMMAND_AUTHORITY_TABLE_DOCS {
        let path = root.join(rel);
        let Ok(text) = fs::read_to_string(&path) else {
            missing.push(format!("could not read `{rel}`"));
            continue;
        };
        if !text.contains(&table) {
            missing.push(format!(
                "`{rel}` does not match the exact tidefsctl command authority table from COMMAND_SURFACES and command_admission"
            ));
        }
    }
}

fn command_authority_table_from_workspace(root: &Path) -> Result<String, String> {
    let classification =
        fs::read_to_string(root.join("apps/tidefsctl/src/commands/classification.rs"))
            .map_err(|err| format!("read tidefsctl command classification registry: {err}"))?;
    let authz = fs::read_to_string(root.join("apps/tidefsctl/src/commands/authz.rs"))
        .map_err(|err| format!("read tidefsctl command admission registry: {err}"))?;

    render_command_authority_table(
        parse_command_surfaces(&classification)?,
        parse_command_admissions(&authz)?,
    )
}

fn render_command_authority_table(
    surfaces: Vec<CommandSurfaceFact>,
    mut admissions: BTreeMap<String, String>,
) -> Result<String, String> {
    let mut table = String::from("| Command | Class | Routing | Admission | Help | Summary |\n");
    table.push_str("|---|---|---|---|---|---|\n");

    for surface in surfaces {
        let admission = admissions
            .remove(&surface.path)
            .ok_or_else(|| format!("missing command_admission entry for `{}`", surface.path))?;
        table.push_str("| `");
        table.push_str(&surface.path);
        table.push_str("` | `");
        table.push_str(&surface.class);
        table.push_str("` | `");
        table.push_str(&surface.routing);
        table.push_str("` | `");
        table.push_str(&admission);
        table.push_str("` | `");
        table.push_str(if surface.class == "removed-or-unsupported" {
            "hidden"
        } else {
            "visible"
        });
        table.push_str("` | ");
        table.push_str(&surface.summary);
        table.push_str(" |\n");
    }

    if !admissions.is_empty() {
        let extra = admissions.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(format!(
            "command_admission entries are not present in COMMAND_SURFACES: {extra}"
        ));
    }

    Ok(table)
}

fn parse_command_surfaces(source: &str) -> Result<Vec<CommandSurfaceFact>, String> {
    let array = source_array_body(source, "pub(crate) const COMMAND_SURFACES")
        .ok_or_else(|| "missing COMMAND_SURFACES array".to_string())?;
    let mut surfaces = Vec::new();

    for entry in array.split("CommandSurface {").skip(1) {
        let block = entry
            .split_once("},")
            .map(|(block, _)| block)
            .ok_or_else(|| "unterminated CommandSurface entry".to_string())?;
        surfaces.push(CommandSurfaceFact {
            path: extract_string_field(block, "path")?,
            class: command_class_label(&extract_enum_field(block, "class", "CommandClass::")?)?
                .to_string(),
            routing: routing_label(&extract_enum_field(block, "routing", "RoutingSemantics::")?)?
                .to_string(),
            summary: extract_string_field(block, "summary")?,
        });
    }

    if surfaces.is_empty() {
        return Err("COMMAND_SURFACES did not yield any command surfaces".to_string());
    }

    Ok(surfaces)
}

fn parse_command_admissions(source: &str) -> Result<BTreeMap<String, String>, String> {
    let mut admissions = BTreeMap::new();
    for (array, label) in [
        ("LOCAL_ONLY_COMMANDS", "local-only"),
        (
            "LOCAL_ONLY_WHEN_MUTATING_COMMANDS",
            "local-only-when-mutating",
        ),
        ("UNGUARDED_COMMANDS", "unguarded"),
    ] {
        for command in parse_string_array(source, array)? {
            if let Some(previous) = admissions.insert(command.clone(), label.to_string()) {
                return Err(format!(
                    "`{command}` appears in multiple command_admission buckets: {previous} and {label}"
                ));
            }
        }
    }
    Ok(admissions)
}

fn parse_string_array(source: &str, const_name: &str) -> Result<Vec<String>, String> {
    let body = source_array_body(source, const_name)
        .ok_or_else(|| format!("missing `{const_name}` array"))?;
    parse_string_literals(body)
}

fn source_array_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let start = source.find(name)?;
    let after_name = &source[start..];
    let array_start = after_name.find("= &[")? + 4;
    let after_open = &after_name[array_start..];
    let array_end = after_open.find("];")?;
    Some(&after_open[..array_end])
}

fn extract_string_field(block: &str, field: &str) -> Result<String, String> {
    let marker = format!("{field}:");
    let after_field = block
        .split_once(&marker)
        .map(|(_, after)| after)
        .ok_or_else(|| format!("missing `{field}` field in CommandSurface entry"))?;
    parse_first_string_literal(after_field)
        .ok_or_else(|| format!("missing string literal for `{field}` field"))
}

fn extract_enum_field(block: &str, field: &str, prefix: &str) -> Result<String, String> {
    let marker = format!("{field}:");
    let after_field = block
        .split_once(&marker)
        .map(|(_, after)| after)
        .ok_or_else(|| format!("missing `{field}` field in CommandSurface entry"))?;
    let after_prefix = after_field
        .split_once(prefix)
        .map(|(_, after)| after)
        .ok_or_else(|| format!("missing `{prefix}` enum value for `{field}` field"))?;
    let value = after_prefix
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    if value.is_empty() {
        Err(format!("empty enum value for `{field}` field"))
    } else {
        Ok(value)
    }
}

fn parse_string_literals(input: &str) -> Result<Vec<String>, String> {
    let mut literals = Vec::new();
    let mut rest = input;

    while let Some(literal) = parse_first_string_literal(rest) {
        let start = rest
            .find('"')
            .expect("literal parser found a quoted string");
        let consumed = quoted_literal_len(&rest[start..])
            .ok_or_else(|| "unterminated string literal".to_string())?;
        literals.push(literal);
        rest = &rest[start + consumed..];
    }

    Ok(literals)
}

fn parse_first_string_literal(input: &str) -> Option<String> {
    let start = input.find('"')?;
    let quoted = &input[start..];
    let mut out = String::new();
    let mut escaped = false;

    for ch in quoted[1..].chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(out);
        }
        out.push(ch);
    }

    None
}

fn quoted_literal_len(input: &str) -> Option<usize> {
    let mut escaped = false;
    for (offset, ch) in input[1..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(offset + 2);
        }
    }
    None
}

fn command_class_label(value: &str) -> Result<&'static str, String> {
    match value {
        "PublicOperator" => Ok("public-operator"),
        "UserspaceHarness" => Ok("userspace-harness"),
        "OperatorDiagnostic" => Ok("operator-diagnostic"),
        "Prototype" => Ok("prototype"),
        "DevelopmentDiagnostic" => Ok("development-diagnostic"),
        "RemovedOrUnsupported" => Ok("removed-or-unsupported"),
        other => Err(format!("unknown CommandClass::{other}")),
    }
}

fn routing_label(value: &str) -> Result<&'static str, String> {
    match value {
        "NoLivePoolState" => Ok("no-live-pool-state"),
        "LiveOwner" => Ok("live-owner"),
        "LiveOwnerOrOfflineInput" => Ok("live-owner-or-offline-input"),
        "OfflineDiscoveryOrImportInput" => Ok("offline-discovery-or-import-input"),
        "UserspaceHarness" => Ok("userspace-harness"),
        "PassiveDiagnostic" => Ok("passive-diagnostic"),
        "PrototypeOnly" => Ok("prototype-only"),
        "DevelopmentExercise" => Ok("development-exercise"),
        "Removed" => Ok("removed"),
        other => Err(format!("unknown RoutingSemantics::{other}")),
    }
}

fn scan_public_claim_surfaces(root: &Path, missing: &mut Vec<String>) {
    for rel in CLAIMS_GATE_SCANNED_DOCS {
        let path = root.join(rel);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                missing.push(format!("read {rel}: {err}"));
                continue;
            }
        };
        for (line_number, line) in text.lines().enumerate() {
            if line_has_present_tense_overclaim(line) {
                missing.push(format!(
                    "{rel}:{} contains an unframed current-capability claim: {}",
                    line_number + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn line_has_present_tense_overclaim(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if !CLAIMS_GATE_SENSITIVE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        return false;
    }
    !line_has_allowed_claim_frame(&lower)
}

fn line_has_allowed_claim_frame(lower_line: &str) -> bool {
    CLAIMS_GATE_ALLOWED_FRAMES
        .iter()
        .any(|frame| lower_line.contains(frame))
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    if !root.join(rel).is_file() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let path = root.join(rel);
    let Ok(text) = fs::read_to_string(&path) else {
        missing.push(format!("could not read `{rel}`"));
        return;
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("`{rel}` missing marker `{marker}`"));
        }
    }
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use tidefs_validation::evidence_artifact_manifest::{
        content_digest_for_bytes, BlockingIssueRef, EvidenceArtifactManifest,
        EVIDENCE_ARTIFACT_MANIFEST_VERSION,
    };
    use tidefs_validation::validation_schema::ValidationTier;
    use tidefs_validation::validation_status::ValidationStatus;

    use super::{
        build_claim_validation_receipt, claims_gate_rules, line_has_present_tense_overclaim,
        parse_claim_registry, parse_command_admissions, parse_command_surfaces,
        render_claim_registry_doc, render_claim_validation_summary, render_command_authority_table,
        validate_claim_record, validate_crash_claims_gate_review_artifact_content,
        validate_model_crash_matrix_artifact_content, validate_registered_crash_artifacts,
        validate_runtime_crash_artifact_content, ClaimEvidenceArtifact, ClaimEvidenceRequirement,
        ClaimGateRuleTopic, ClaimReceiptStatus, ClaimRecord, ClaimStatus, EvidenceClassStatus,
        APP_INDEX_LIMITATION_MARKERS, CLAIMS_GATE_POLICY_SPEC, CLAIMS_GATE_REQUIRED_COMMAND,
        CLAIMS_GATE_REVIEW_EVIDENCE_CLASS, CLAIMS_GATE_SCANNED_DOCS, CRASH_CLAIMS_GATE_REVIEW_PATH,
        CRASH_CLAIMS_GATE_REVIEW_SCOPE, CRASH_CLAIMS_GATE_REVIEW_SOURCE, CRASH_CLAIM_IDS,
        CRASH_MODEL_EVIDENCE_SCOPE, CRASH_MODEL_EVIDENCE_SOURCE, CRASH_MODEL_MATRIX_PATH,
        CRATE_INDEX_LIMITATION_MARKERS, LOCAL_VFS_RENAME_CRASH_CLAIM_ID,
        LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID, MODEL_CRASH_MATRIX_EVIDENCE_CLASS,
        REQUIRED_INITIAL_CLAIMS, RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS,
        RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS, STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
    };

    #[test]
    fn claims_gate_policy_covers_current_claim_boundaries() {
        let rules = claims_gate_rules();
        assert_eq!(rules.len(), 9);

        for topic in [
            ClaimGateRuleTopic::ScannedPublishingSurfaces,
            ClaimGateRuleTopic::ForbiddenCurrentCapabilityClaims,
            ClaimGateRuleTopic::RequiredLimitationMarkers,
            ClaimGateRuleTopic::WorkStateAuthority,
            ClaimGateRuleTopic::UnreleasedAuthority,
            ClaimGateRuleTopic::EvidenceBeforeEscalation,
            ClaimGateRuleTopic::MountedTransformAuthority,
            ClaimGateRuleTopic::OperatorCommandClassification,
            ClaimGateRuleTopic::ClaimRegistryAuthority,
        ] {
            assert!(
                rules.iter().any(|rule| rule.topic == topic),
                "claims gate should cover {}",
                topic.human_name()
            );
            assert!(topic.stable_id().starts_with("claims_gate."));
        }

        for marker in [
            "OpenZFS/Ceph",
            "production-ready",
            "POSIX-complete",
            "GitHub issue and pull request state",
            "public release",
            "proof",
            "Mounted device-level compression",
            "raw-store inventory",
            "tidefsctl command classification",
            "final distributed operator UAPI",
            "validation/claims.toml",
        ] {
            assert!(
                rules.iter().any(|rule| rule.rule.contains(marker))
                    || CLAIMS_GATE_POLICY_SPEC.contains(marker),
                "claims gate should mention {marker}"
            );
        }

        assert!(CLAIMS_GATE_POLICY_SPEC.contains("matching proof"));
        assert!(CLAIMS_GATE_POLICY_SPEC.contains("unreleased internal TideFS paths"));
        assert!(CLAIMS_GATE_POLICY_SPEC.contains("tidefsctl command classification"));
        assert!(CLAIMS_GATE_REQUIRED_COMMAND.contains("check-claims-gate"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"README.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"apps/README.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"crates/README.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/REVIEW_TODO_REGISTER.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/UNRELEASED_AUTHORITY_POLICY.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/BLAKE3_USAGE_POLICY.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/WHOLE_REPO_REVIEW.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/workspace-package-classification.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/CLAIM_REGISTRY.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS
            .contains(&"docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md"));
    }

    #[test]
    fn claim_registry_records_initial_claims_and_statuses() {
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let ids = registry
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect::<Vec<_>>();

        for required_id in REQUIRED_INITIAL_CLAIMS {
            assert!(
                ids.contains(required_id),
                "registry should contain initial claim {required_id}"
            );
        }
        assert!(registry
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Planned));
        assert!(registry
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Blocked));
        assert_eq!(ClaimStatus::Planned.as_str(), "planned");
        assert_eq!(ClaimStatus::Blocked.as_str(), "blocked");
        assert_eq!(ClaimStatus::Validated.as_str(), "validated");
        assert_eq!(ClaimStatus::Invalid.as_str(), "invalid");
    }

    #[test]
    fn claim_registry_doc_matches_registry() {
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let generated = render_claim_registry_doc(&registry);
        assert_eq!(generated, include_str!("../../../docs/CLAIM_REGISTRY.md"));
        assert!(generated.contains("offload.ready.non_authoritative.v1"));
        assert!(generated.contains("BLOCKED exits successfully for focused validation"));
    }

    #[test]
    fn validate_claim_receipt_names_missing_no_hidden_queue_evidence() {
        let root = workspace_root();
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == LOCAL_VFS_RENAME_CRASH_CLAIM_ID)
            .expect("local VFS rename atomic crash claim registered");

        let receipt = build_claim_validation_receipt(&root, SystemTime::UNIX_EPOCH, claim);
        assert_eq!(receipt.status, ClaimReceiptStatus::Blocked);

        let runtime = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS)
            .expect("runtime crash evidence receipt");
        assert_eq!(runtime.status, EvidenceClassStatus::Present);
        assert_eq!(
            runtime.artifact_path,
            "validation/artifacts/crash-oracle/local-vfs-rename-crash-runtime.json"
        );
        assert_eq!(runtime.validation_tier, "mounted-userspace");
        assert!(runtime.blocking_issues.is_empty());
        assert!(
            runtime.details.is_empty(),
            "runtime artifact verifier should accept committed local VFS rename crash evidence: {:?}",
            runtime.details
        );

        let no_hidden = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == "no-hidden-queue-gate")
            .expect("rename no-hidden queue evidence receipt");
        assert_eq!(no_hidden.status, EvidenceClassStatus::Missing);
        assert_eq!(
            no_hidden.artifact_path,
            "validation/performance/no-hidden-queues.toml"
        );
        assert_eq!(no_hidden.validation_tier, "cargo-unit");
        assert_eq!(no_hidden.blocking_issues, vec!["#720".to_string()]);
        assert!(no_hidden.details.iter().any(|detail| detail
            .contains("no evidence_artifacts entry registers class `no-hidden-queue-gate`")));

        let model = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == MODEL_CRASH_MATRIX_EVIDENCE_CLASS)
            .expect("model crash matrix receipt");
        assert_eq!(model.status, EvidenceClassStatus::Present);

        let summary = render_claim_validation_summary(&receipt);
        assert!(summary.contains("status: BLOCKED"));
        assert!(summary.contains("class: runtime-namespace-crash-artifact"));
        assert!(summary.contains("class: no-hidden-queue-gate"));
        assert!(summary.contains("blocking_issues: #720"));
        assert!(!summary.contains("blocking_issues: #596"));
    }

    #[test]
    fn validate_claim_receipt_accepts_local_write_runtime_artifact() {
        let root = workspace_root();
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == LOCAL_VFS_WRITE_FSYNC_CRASH_CLAIM_ID)
            .expect("local VFS write/fsync crash claim registered");

        let receipt = build_claim_validation_receipt(&root, SystemTime::UNIX_EPOCH, claim);
        assert_eq!(receipt.status, ClaimReceiptStatus::Pass);

        let runtime = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS)
            .expect("runtime crash evidence receipt");
        assert_eq!(runtime.status, EvidenceClassStatus::Present);
        assert_eq!(
            runtime.artifact_path,
            "validation/artifacts/crash-oracle/local-vfs-write-fsync-runtime-crash.json"
        );
        assert_eq!(runtime.validation_tier, "mounted-userspace");
        assert!(
            runtime.blocking_issues.is_empty(),
            "present runtime artifact should not keep #493 as a blocking issue"
        );
        assert!(
            runtime.details.is_empty(),
            "runtime artifact verifier should accept committed local VFS crash evidence: {:?}",
            runtime.details
        );

        let summary = render_claim_validation_summary(&receipt);
        assert!(summary.contains("status: PASS"));
        assert!(summary.contains("class: runtime-crash-oracle"));
        assert!(!summary.contains("blocking_issues: #493"));
    }

    #[test]
    fn validate_claim_json_receipt_is_parseable() {
        let root = workspace_root();
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == LOCAL_VFS_RENAME_CRASH_CLAIM_ID)
            .expect("local VFS rename atomic crash claim registered");

        let receipt = build_claim_validation_receipt(&root, SystemTime::UNIX_EPOCH, claim);
        let json = serde_json::to_value(&receipt).expect("receipt serializes to JSON");
        assert_eq!(json["claim_id"], LOCAL_VFS_RENAME_CRASH_CLAIM_ID);
        assert_eq!(json["status"], "BLOCKED");
        let runtime = json["required_evidence"]
            .as_array()
            .expect("required evidence array")
            .iter()
            .find(|entry| entry["class"] == RUNTIME_NAMESPACE_CRASH_ARTIFACT_EVIDENCE_CLASS)
            .expect("runtime crash evidence entry");
        assert_eq!(runtime["status"], "PRESENT");
        assert_eq!(runtime["validation_tier"], "mounted-userspace");
        assert_eq!(
            runtime["artifact_path"],
            "validation/artifacts/crash-oracle/local-vfs-rename-crash-runtime.json"
        );
        let no_hidden = json["required_evidence"]
            .as_array()
            .expect("required evidence array")
            .iter()
            .find(|entry| entry["class"] == "no-hidden-queue-gate")
            .expect("no-hidden queue evidence entry");
        assert_eq!(no_hidden["status"], "MISSING");
        assert_eq!(no_hidden["validation_tier"], "cargo-unit");
        assert_eq!(
            no_hidden["artifact_path"],
            "validation/performance/no-hidden-queues.toml"
        );
    }

    #[test]
    fn validate_claim_fails_closed_for_planned_status() {
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == "scrub.foreground_read.protected.v1")
            .expect("planned scrub claim registered");
        let failures = validate_claim_record(
            std::path::Path::new("."),
            std::time::SystemTime::now(),
            claim,
        );
        assert!(failures
            .iter()
            .any(|failure| failure.contains("is planned")));
        assert!(failures
            .iter()
            .any(|failure| failure.contains("Scrub/read isolation authority")));
    }

    #[test]
    fn validate_claim_requires_missing_and_fresh_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact_path = temp.path().join("evidence.txt");
        fs::write(&artifact_path, "old evidence").expect("write evidence");
        let artifact_modified = fs::metadata(&artifact_path)
            .and_then(|metadata| metadata.modified())
            .expect("artifact mtime");
        let registry_modified = artifact_modified + Duration::from_secs(1);

        let mut claim = ClaimRecord {
            id: "example.validated.v1".to_string(),
            status: ClaimStatus::Validated,
            scope: "test scope".to_string(),
            required_evidence_classes: vec!["runtime-artifact".to_string()],
            evidence_requirements: Vec::new(),
            blockers: Vec::new(),
            generated_doc: "Validated fixture claim.".to_string(),
            evidence_artifacts: Vec::new(),
        };
        let missing = validate_claim_record(temp.path(), registry_modified, &claim);
        assert!(missing
            .iter()
            .any(|failure| failure.contains("missing evidence artifact")));

        claim.evidence_artifacts.push(ClaimEvidenceArtifact {
            class: "runtime-artifact".to_string(),
            path: "evidence.txt".to_string(),
            ..Default::default()
        });
        let stale = validate_claim_record(temp.path(), registry_modified, &claim);
        assert!(stale
            .iter()
            .any(|failure| failure.contains("stale evidence artifact")));
    }

    #[test]
    fn validate_claim_accepts_manifest_backed_evidence_requirement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact_body = "manifest-backed evidence body";
        write_artifact(temp.path(), "evidence/summary.txt", artifact_body);
        write_manifest_fixture(
            temp.path(),
            "evidence/summary.manifest.json",
            "example.manifest.validated.v1",
            "cargo-fixture",
            "evidence/summary.txt",
            artifact_body,
            ValidationStatus::Pass,
            Vec::new(),
        );
        let claim = manifest_fixture_claim(
            "example.manifest.validated.v1",
            ClaimStatus::Validated,
            Vec::new(),
            Vec::new(),
        );

        let receipt = build_claim_validation_receipt(&temp.path(), SystemTime::UNIX_EPOCH, &claim);
        assert_eq!(receipt.status, ClaimReceiptStatus::Pass);
        let evidence = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == "cargo-fixture")
            .expect("manifest-backed evidence receipt");
        assert_eq!(evidence.status, EvidenceClassStatus::Present);
        assert_eq!(evidence.artifact_path, "evidence/summary.txt");
        assert_eq!(
            evidence.manifest_path.as_deref(),
            Some("evidence/summary.manifest.json")
        );
        let expected_digest = content_digest_for_bytes(artifact_body.as_bytes());
        assert_eq!(
            evidence.content_digest.as_deref(),
            Some(expected_digest.as_str())
        );
        assert_eq!(evidence.run_id.as_deref(), Some("fixture-run-810/1"));
        assert_eq!(evidence.source_ref.as_deref(), Some("fixture-source-ref"));
        assert_eq!(evidence.outcome.as_deref(), Some("PASS"));
        assert_eq!(
            evidence.residual_risk.as_deref(),
            Some("Fixture proves manifest gate behavior only.")
        );
        assert!(evidence.details.is_empty(), "{:?}", evidence.details);
        assert!(validate_claim_record(&temp.path(), SystemTime::UNIX_EPOCH, &claim).is_empty());

        let summary = render_claim_validation_summary(&receipt);
        assert!(summary.contains("manifest_path: evidence/summary.manifest.json"));
        assert!(summary.contains("run_id: fixture-run-810/1"));
        assert!(summary.contains("source_ref: fixture-source-ref"));
        assert!(summary.contains("residual_risk: Fixture proves manifest gate behavior only."));
    }

    #[test]
    fn validate_claim_reports_blocked_missing_manifest_requirement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let claim = manifest_fixture_claim(
            "example.manifest.blocked.v1",
            ClaimStatus::Blocked,
            vec!["GitHub issue #810 fixture blocker".to_string()],
            vec!["#810".to_string()],
        );

        let receipt = build_claim_validation_receipt(&temp.path(), SystemTime::UNIX_EPOCH, &claim);
        assert_eq!(receipt.status, ClaimReceiptStatus::Blocked);
        let evidence = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == "cargo-fixture")
            .expect("manifest-backed evidence receipt");
        assert_eq!(evidence.status, EvidenceClassStatus::Missing);
        assert_eq!(evidence.blocking_issues, vec!["#810".to_string()]);
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.contains("missing evidence manifest")));
    }

    #[test]
    fn validate_claim_fails_closed_for_malformed_manifest_requirement() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_artifact(temp.path(), "evidence/summary.txt", "evidence body");
        write_artifact(
            temp.path(),
            "evidence/summary.manifest.json",
            "{ this is not valid manifest JSON",
        );
        let claim = manifest_fixture_claim(
            "example.manifest.validated.v1",
            ClaimStatus::Validated,
            Vec::new(),
            Vec::new(),
        );

        let receipt = build_claim_validation_receipt(&temp.path(), SystemTime::UNIX_EPOCH, &claim);
        assert_eq!(receipt.status, ClaimReceiptStatus::Fail);
        let evidence = receipt
            .required_evidence
            .iter()
            .find(|evidence| evidence.class == "cargo-fixture")
            .expect("manifest-backed evidence receipt");
        assert_eq!(evidence.status, EvidenceClassStatus::Malformed);
        assert!(evidence
            .details
            .iter()
            .any(|detail| detail.contains("malformed or unsupported")));

        let failures = validate_claim_record(&temp.path(), SystemTime::UNIX_EPOCH, &claim);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("malformed or unsupported")));
    }

    #[test]
    fn claims_gate_accepts_current_crash_model_artifact_scope() {
        let root = workspace_root();
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID)
            .expect("storage write/fsync claim registered");
        let artifact = claim
            .evidence_artifacts
            .iter()
            .find(|artifact| artifact.class == MODEL_CRASH_MATRIX_EVIDENCE_CLASS)
            .expect("model crash matrix registered");

        let failures = validate_model_crash_matrix_artifact_content(&root, claim, artifact);
        assert!(failures.is_empty(), "{failures:#?}");

        let registry_failures =
            validate_registered_crash_artifacts(&root, SystemTime::UNIX_EPOCH, &registry);
        assert!(registry_failures.is_empty(), "{registry_failures:#?}");
    }

    #[test]
    fn runtime_crash_evidence_rejects_model_matrix_scope() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_current_model_matrix(temp.path());
        let claim = validated_crash_claim(
            STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
            vec![RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS.to_string()],
            Vec::new(),
        );
        let artifact = crash_artifact(
            RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS,
            CRASH_MODEL_MATRIX_PATH,
            CRASH_MODEL_EVIDENCE_SOURCE,
            CRASH_MODEL_EVIDENCE_SCOPE,
        );

        let failures = validate_runtime_crash_artifact_content(temp.path(), &claim, &artifact);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("must not point at model-only crash matrix")));
        assert!(failures
            .iter()
            .any(|failure| failure.contains("whose declared scope is model-only")));
    }

    #[test]
    fn validated_crash_claim_requires_claims_gate_review_artifact() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_current_model_matrix(temp.path());
        write_runtime_crash_artifact(
            temp.path(),
            "validation/artifacts/crash-oracle/runtime.json",
        );

        let claim = validated_crash_claim(
            STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
            vec![
                MODEL_CRASH_MATRIX_EVIDENCE_CLASS.to_string(),
                RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS.to_string(),
                CLAIMS_GATE_REVIEW_EVIDENCE_CLASS.to_string(),
            ],
            vec![
                crash_artifact(
                    MODEL_CRASH_MATRIX_EVIDENCE_CLASS,
                    CRASH_MODEL_MATRIX_PATH,
                    CRASH_MODEL_EVIDENCE_SOURCE,
                    CRASH_MODEL_EVIDENCE_SCOPE,
                ),
                crash_artifact(
                    RUNTIME_CRASH_ORACLE_EVIDENCE_CLASS,
                    "validation/artifacts/crash-oracle/runtime.json",
                    "local-runtime-crash-oracle",
                    "runtime-crash-injection",
                ),
            ],
        );

        let failures = validate_claim_record(temp.path(), SystemTime::UNIX_EPOCH, &claim);
        assert!(failures
            .iter()
            .any(|failure| failure
                .contains("missing evidence artifact for class `claims-gate-review`")));
    }

    #[test]
    fn crash_review_artifact_rejects_malformed_or_stale_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_malformed_crash_review(temp.path());
        let claim = validated_crash_claim(
            STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
            vec![CLAIMS_GATE_REVIEW_EVIDENCE_CLASS.to_string()],
            Vec::new(),
        );
        let artifact = crash_artifact(
            CLAIMS_GATE_REVIEW_EVIDENCE_CLASS,
            CRASH_CLAIMS_GATE_REVIEW_PATH,
            CRASH_CLAIMS_GATE_REVIEW_SOURCE,
            CRASH_CLAIMS_GATE_REVIEW_SCOPE,
        );

        let malformed =
            validate_crash_claims_gate_review_artifact_content(temp.path(), &claim, &artifact);
        assert!(malformed
            .iter()
            .any(|failure| failure.contains("model/runtime evidence boundary")));

        write_valid_crash_review(temp.path());
        let artifact_path = temp.path().join(CRASH_CLAIMS_GATE_REVIEW_PATH);
        let artifact_modified = fs::metadata(&artifact_path)
            .and_then(|metadata| metadata.modified())
            .expect("review mtime");
        let stale_claim = validated_crash_claim(
            STORAGE_WRITE_FSYNC_CRASH_CLAIM_ID,
            vec![CLAIMS_GATE_REVIEW_EVIDENCE_CLASS.to_string()],
            vec![artifact],
        );
        let stale = validate_claim_record(
            temp.path(),
            artifact_modified + Duration::from_secs(1),
            &stale_claim,
        );
        assert!(stale
            .iter()
            .any(|failure| failure.contains("stale evidence artifact")));
    }

    #[test]
    fn claims_gate_requires_top_level_index_limitations() {
        for marker in [
            "checked package-role authority",
            "operator entrypoint for CLI/UAPI work; TFR-011 and TFR-019 remain open",
            "cluster authority remains TFR-017",
            "non-production Local Object Store exercise only",
            "not production-readiness claims",
        ] {
            assert!(
                APP_INDEX_LIMITATION_MARKERS.contains(&marker),
                "apps index should require marker {marker}"
            );
        }

        for marker in [
            "current package-role authority is `docs/workspace-package-classification.md`",
            "validates that authority against Cargo metadata",
            "only a navigation aid, not a second package table",
            "Capability wording for crates remains behind implementation reality",
            "`docs/CLAIMS_GATE_POLICY.md`",
            "`cargo run -p tidefs-xtask -- check-claims-gate`",
        ] {
            assert!(
                CRATE_INDEX_LIMITATION_MARKERS.contains(&marker),
                "crates index should require marker {marker}"
            );
        }
    }

    #[test]
    fn command_authority_table_changes_with_registry_or_admission_drift() {
        const BASE_CLASSIFICATION: &str = r#"
pub(crate) const COMMAND_SURFACES: &[CommandSurface] = &[
    CommandSurface {
        path: "pool scan",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::OfflineDiscoveryOrImportInput,
        summary: "scan explicit devices for pool labels",
    },
];
"#;
        const TWO_SURFACE_CLASSIFICATION: &str = r#"
pub(crate) const COMMAND_SURFACES: &[CommandSurface] = &[
    CommandSurface {
        path: "pool scan",
        class: CommandClass::PublicOperator,
        routing: RoutingSemantics::OfflineDiscoveryOrImportInput,
        summary: "scan explicit devices for pool labels",
    },
    CommandSurface {
        path: "diag",
        class: CommandClass::OperatorDiagnostic,
        routing: RoutingSemantics::PassiveDiagnostic,
        summary: "collect a redacted local support bundle",
    },
];
"#;
        const BASE_AUTHZ: &str = r#"
const LOCAL_ONLY_COMMANDS: &[&str] = &[];
const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &[];
const UNGUARDED_COMMANDS: &[&str] = &["pool scan"];
"#;
        const TWO_SURFACE_AUTHZ: &str = r#"
const LOCAL_ONLY_COMMANDS: &[&str] = &[];
const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &[];
const UNGUARDED_COMMANDS: &[&str] = &["pool scan", "diag"];
"#;
        const MISSING_AUTHZ: &str = r#"
const LOCAL_ONLY_COMMANDS: &[&str] = &[];
const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &[];
const UNGUARDED_COMMANDS: &[&str] = &[];
"#;
        const EXTRA_AUTHZ: &str = r#"
const LOCAL_ONLY_COMMANDS: &[&str] = &[];
const LOCAL_ONLY_WHEN_MUTATING_COMMANDS: &[&str] = &[];
const UNGUARDED_COMMANDS: &[&str] = &["pool scan", "diag"];
"#;

        let table = fixture_table(BASE_CLASSIFICATION, BASE_AUTHZ).expect("base fixture table");
        let added =
            fixture_table(TWO_SURFACE_CLASSIFICATION, TWO_SURFACE_AUTHZ).expect("added command");
        assert_ne!(
            table, added,
            "adding a command must change the required table"
        );

        let reclassified = fixture_table(
            &BASE_CLASSIFICATION.replace("CommandClass::PublicOperator", "CommandClass::Prototype"),
            BASE_AUTHZ,
        )
        .expect("reclassified command");
        assert_ne!(
            table, reclassified,
            "reclassifying a command must change the required table"
        );

        let rerouted = fixture_table(
            &BASE_CLASSIFICATION.replace(
                "RoutingSemantics::OfflineDiscoveryOrImportInput",
                "RoutingSemantics::PassiveDiagnostic",
            ),
            BASE_AUTHZ,
        )
        .expect("rerouted command");
        assert_ne!(
            table, rerouted,
            "rerouting a command must change the required table"
        );

        let deleted =
            fixture_table(BASE_CLASSIFICATION, BASE_AUTHZ).expect("single-command fixture");
        assert_ne!(
            added, deleted,
            "deleting a command from a larger table must change the required table"
        );

        assert!(fixture_table(BASE_CLASSIFICATION, MISSING_AUTHZ)
            .expect_err("missing admission should fail")
            .contains("missing command_admission entry"));
        assert!(fixture_table(BASE_CLASSIFICATION, EXTRA_AUTHZ)
            .expect_err("extra admission should fail")
            .contains("not present in COMMAND_SURFACES"));
    }

    fn fixture_table(classification: &str, authz: &str) -> Result<String, String> {
        render_command_authority_table(
            parse_command_surfaces(classification)?,
            parse_command_admissions(authz)?,
        )
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn crash_artifact(class: &str, path: &str, source: &str, scope: &str) -> ClaimEvidenceArtifact {
        ClaimEvidenceArtifact {
            class: class.to_string(),
            path: path.to_string(),
            source: Some(source.to_string()),
            scope: Some(scope.to_string()),
        }
    }

    fn validated_crash_claim(
        id: &str,
        required_evidence_classes: Vec<String>,
        evidence_artifacts: Vec<ClaimEvidenceArtifact>,
    ) -> ClaimRecord {
        ClaimRecord {
            id: id.to_string(),
            status: ClaimStatus::Validated,
            scope: "test crash scope".to_string(),
            required_evidence_classes,
            evidence_requirements: Vec::new(),
            blockers: Vec::new(),
            generated_doc: "Validated crash fixture claim.".to_string(),
            evidence_artifacts,
        }
    }

    fn manifest_fixture_claim(
        id: &str,
        status: ClaimStatus,
        blockers: Vec<String>,
        requirement_blocking_issues: Vec<String>,
    ) -> ClaimRecord {
        ClaimRecord {
            id: id.to_string(),
            status,
            scope: "manifest-backed claim fixture".to_string(),
            required_evidence_classes: vec!["cargo-fixture".to_string()],
            evidence_requirements: vec![ClaimEvidenceRequirement {
                class: "cargo-fixture".to_string(),
                path: "evidence/summary.txt".to_string(),
                validation_tier: ValidationTier::CargoUnit,
                manifest_path: Some("evidence/summary.manifest.json".to_string()),
                blocking_issues: requirement_blocking_issues,
            }],
            blockers,
            generated_doc: match status {
                ClaimStatus::Validated => "Validated manifest-backed fixture claim.".to_string(),
                ClaimStatus::Blocked => "Blocked manifest-backed fixture claim.".to_string(),
                ClaimStatus::Planned => "Planned manifest-backed fixture claim.".to_string(),
                ClaimStatus::Invalid => "Invalid manifest-backed fixture claim.".to_string(),
            },
            evidence_artifacts: Vec::new(),
        }
    }

    fn write_manifest_fixture(
        root: &Path,
        manifest_path: &str,
        claim_id: &str,
        evidence_class: &str,
        artifact_path: &str,
        artifact_body: &str,
        outcome: ValidationStatus,
        blocking_issues: Vec<BlockingIssueRef>,
    ) {
        let manifest = EvidenceArtifactManifest {
            manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
            claim_id: claim_id.to_string(),
            evidence_class: evidence_class.to_string(),
            validation_tier: ValidationTier::CargoUnit,
            scope: "manifest-backed cargo fixture".to_string(),
            artifact_path: artifact_path.to_string(),
            content_digest: content_digest_for_bytes(artifact_body.as_bytes()),
            run_id: "fixture-run-810/1".to_string(),
            source_ref: "fixture-source-ref".to_string(),
            outcome,
            residual_risk: "Fixture proves manifest gate behavior only.".to_string(),
            source: "tidefs-xtask-test".to_string(),
            generated_at: "2026-06-22T15:00:00Z".to_string(),
            blocking_issues,
        };
        write_artifact(
            root,
            manifest_path,
            &manifest
                .to_json_pretty()
                .expect("serialize manifest fixture"),
        );
    }

    fn write_current_model_matrix(root: &Path) {
        write_artifact(
            root,
            CRASH_MODEL_MATRIX_PATH,
            include_str!("../../../validation/artifacts/crash-oracle/model-crash-matrices.json"),
        );
    }

    fn write_valid_crash_review(root: &Path) {
        write_artifact(
            root,
            CRASH_CLAIMS_GATE_REVIEW_PATH,
            include_str!("../../../validation/artifacts/crash-oracle/claims-gate-review.toml"),
        );
    }

    fn write_runtime_crash_artifact(root: &Path, rel: &str) {
        write_artifact(
            root,
            rel,
            r#"{
  "evidence_scope": "bounded local runtime crash injection artifact",
  "source": "local-runtime-crash-oracle"
}
"#,
        );
    }

    fn write_malformed_crash_review(root: &Path) {
        let claim_ids = CRASH_CLAIM_IDS
            .iter()
            .map(|claim_id| format!("\"{claim_id}\""))
            .collect::<Vec<_>>()
            .join(", ");
        write_artifact(
            root,
            CRASH_CLAIMS_GATE_REVIEW_PATH,
            &format!(
                r#"artifact_version = 1
evidence_class = "claims-gate-review"
source = "claims-gate"
scope = "model-runtime-boundary-review"
issue = 329
model_artifact = "validation/artifacts/crash-oracle/model-crash-matrices.json"
model_evidence_class = "model-crash-matrix"
model_evidence_scope = "runtime proof"
runtime_claim_boundary = "runtime proof exists"
reviewed_claim_ids = [{claim_ids}]
missing_runtime_evidence_classes = ["runtime-crash-oracle"]
runtime_evidence_status = "complete"
decision = "validated"
boundary_review = ["runtime evidence is complete"]
non_claims = ["none"]
"#
            ),
        );
    }

    fn write_artifact(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create artifact parent");
        }
        fs::write(path, contents).expect("write artifact");
    }

    #[test]
    fn claims_gate_rejects_unframed_current_capability_claims() {
        assert!(line_has_present_tense_overclaim(
            "TideFS is production-ready for general use."
        ));
        assert!(line_has_present_tense_overclaim(
            "TideFS is an OpenZFS/Ceph successor."
        ));
        assert!(line_has_present_tense_overclaim(
            "The RDMA data path exists for the product."
        ));
    }

    #[test]
    fn claims_gate_allows_future_or_negated_capability_context() {
        assert!(!line_has_present_tense_overclaim(
            "TideFS is not production-ready."
        ));
        assert!(!line_has_present_tense_overclaim(
            "The OpenZFS/Ceph successor claim is prohibited until proof exists."
        ));
        assert!(!line_has_present_tense_overclaim(
            "RDMA data path work is future optional transport acceleration."
        ));
    }

    #[test]
    fn claims_gate_rejects_unframed_full_kernel_claims() {
        assert!(line_has_present_tense_overclaim(
            "TideFS achieves full-kernel operation in this release."
        ));
        assert!(line_has_present_tense_overclaim(
            "Full kernel mode is now operational."
        ));
    }

    #[test]
    fn claims_gate_rejects_unframed_mounted_transform_claims() {
        assert!(line_has_present_tense_overclaim(
            "TideFS has mounted compression for normal filesystem mounts."
        ));
        assert!(line_has_present_tense_overclaim(
            "TideFS provides mounted device-level encryption today."
        ));
    }

    #[test]
    fn claims_gate_allows_blocked_mounted_transform_context() {
        assert!(!line_has_present_tense_overclaim(
            "Mounted device-level compression is blocked behind the raw-store inventory."
        ));
        assert!(!line_has_present_tense_overclaim(
            "Object-store compression is helper/library tier, not an end-to-end mounted filesystem support claim."
        ));
    }

    #[test]
    fn claims_gate_allows_k7_13_residency_framed_kernel_context() {
        assert!(!line_has_present_tense_overclaim(
            "Full-kernel mode must not require a FUSE daemon."
        ));
        assert!(!line_has_present_tense_overclaim(
            "The K7-13 full-kernel residency invariant requires no FUSE daemon."
        ));
        assert!(!line_has_present_tense_overclaim(
            "not yet full-kernel capable"
        ));
    }

    #[test]
    fn claims_gate_rejects_unframed_final_distributed_operator_uapi_claims() {
        assert!(line_has_present_tense_overclaim(
            "cluster placement exercise is final distributed operator UAPI."
        ));
        assert!(!line_has_present_tense_overclaim(
            "cluster placement exercise is not final distributed operator UAPI."
        ));
        assert!(!line_has_present_tense_overclaim(
            "cluster pool create remains a prototype and is not final distributed operator UAPI."
        ));
    }
}
