use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const CLAIMS_GATE_POLICY_SPEC: &str = "claims gate: publishing-facing TideFS docs must not claim current OpenZFS/Ceph successor, production-ready, POSIX-complete, distributed, kernelspace, RDMA data-path, or final distributed operator UAPI capability before matching proof exists; unreleased internal TideFS paths must not be framed as product compatibility or migration promises without a real external boundary; tidefsctl command classification/admission is the public operator/harness/diagnostic/prototype/removed boundary; validation/claims.toml is the stable claim registry authority";
pub const CLAIMS_GATE_REQUIRED_COMMAND: &str = "cargo run -p tidefs-xtask -- check-claims-gate";

pub const CLAIMS_GATE_SCANNED_DOCS: &[&str] = &[
    "README.md",
    "apps/README.md",
    "crates/README.md",
    "docs/00_user_requirements.md",
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

const REQUIRED_INITIAL_CLAIMS: &[&str] = &[
    "storage.write_fsync.crash_safety.v1",
    "namespace.rename.atomicity.v1",
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
    blockers: Vec<String>,
    generated_doc: String,
    #[serde(default)]
    evidence_artifacts: Vec<ClaimEvidenceArtifact>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimEvidenceArtifact {
    class: String,
    path: String,
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
        writeln!(f, "claim validation failed closed:")?;
        for item in &self.failures {
            writeln!(f, "- {item}")?;
        }
        Ok(())
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
            "Scaffolding note",
            "**not** send or collect messages itself",
            "Real transport dispatch belongs to Review debt TFR-017",
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

pub fn validate_claim_current_workspace(id: &str) -> Result<(), ClaimValidationError> {
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
    let failures = validate_claim_record(&root, registry_modified, claim);
    if failures.is_empty() {
        println!(
            "claim `{}` validated: {} evidence artifact(s) fresh",
            claim.id,
            claim.evidence_artifacts.len()
        );
        Ok(())
    } else {
        Err(ClaimValidationError { failures })
    }
}

fn check_claim_registry_docs(root: &Path, missing: &mut Vec<String>) {
    let (registry, _) = match load_claim_registry(root) {
        Ok(registry) => registry,
        Err(err) => {
            missing.push(err);
            return;
        }
    };

    for err in validate_claim_registry(&registry) {
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
        return failures;
    }

    let mut failures = Vec::new();
    for class in &claim.required_evidence_classes {
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
    }
    failures
}

fn render_claim_registry_doc(registry: &ClaimRegistry) -> String {
    let mut out = String::new();
    out.push_str("# TideFS Claim Registry\n\n");
    out.push_str("Maturity: generated claim registry.\n\n");
    out.push_str("This file is generated from `validation/claims.toml` by `cargo run -p tidefs-xtask -- check-claims-gate`. Edit the registry, not this document.\n\n");
    out.push_str("`validate-claim <id>` succeeds only for `validated` claims with fresh evidence artifacts. Planned, blocked, and invalid claims fail closed and remain non-product claims.\n\n");
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
    use std::time::Duration;

    use super::{
        claims_gate_rules, line_has_present_tense_overclaim, parse_claim_registry,
        parse_command_admissions, parse_command_surfaces, render_claim_registry_doc,
        render_command_authority_table, validate_claim_record, ClaimEvidenceArtifact,
        ClaimGateRuleTopic, ClaimRecord, ClaimStatus, APP_INDEX_LIMITATION_MARKERS,
        CLAIMS_GATE_POLICY_SPEC, CLAIMS_GATE_REQUIRED_COMMAND, CLAIMS_GATE_SCANNED_DOCS,
        CRATE_INDEX_LIMITATION_MARKERS, REQUIRED_INITIAL_CLAIMS,
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
        assert!(generated.contains("Planned, blocked, and invalid claims fail closed"));
    }

    #[test]
    fn validate_claim_fails_closed_for_planned_status() {
        let registry = parse_claim_registry(include_str!("../../../validation/claims.toml"))
            .expect("claim registry parses");
        let claim = registry
            .claims
            .iter()
            .find(|claim| claim.id == "offload.ready.non_authoritative.v1")
            .expect("offload claim registered");
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
            .any(|failure| failure.contains("NEXTGEN-007")));
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
        });
        let stale = validate_claim_record(temp.path(), registry_modified, &claim);
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
