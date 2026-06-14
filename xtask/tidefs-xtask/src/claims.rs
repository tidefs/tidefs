use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const CLAIMS_GATE_POLICY_SPEC: &str = "claims gate: publishing-facing TideFS docs must not claim current OpenZFS/Ceph successor, production-ready, POSIX-complete, distributed, kernelspace, RDMA data-path, or final distributed operator UAPI capability before matching proof exists; unreleased internal TideFS paths must not be framed as product compatibility or migration promises without a real external boundary; tidefsctl command classification is the public operator/harness/diagnostic/prototype/removed boundary";
pub const CLAIMS_GATE_REQUIRED_COMMAND: &str = "cargo run -p tidefs-xtask -- check-claims-gate";

pub const CLAIMS_GATE_SCANNED_DOCS: &[&str] = &[
    "README.md",
    "apps/README.md",
    "crates/README.md",
    "docs/00_user_requirements.md",
    "docs/CLAIMS_GATE_POLICY.md",
    "docs/GETTING_STARTED.md",
    "docs/INDEX.md",
    "docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md",
    "docs/PREVIEW_USER_MANUAL.md",
    "docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md",
    "docs/REVIEW_TODO_REGISTER.md",
    "docs/UNRELEASED_AUTHORITY_POLICY.md",
    "docs/WHOLE_REPO_REVIEW.md",
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
    "inventory, not a production-readiness claim",
    "`tidefsctl`",
    "`TFR-011`/`TFR-019` review",
    "non-production Local Filesystem demo",
    "storage-node cluster authority remains under `TFR-017`",
    "non-production Local Object Store demo",
];

const CRATE_INDEX_LIMITATION_MARKERS: &[&str] = &[
    "package counts and tables below are stale",
    "review input, not current package authority",
    "not current package authority",
    "source ownership index, not release proof",
    "Capability claims",
    "must follow `docs/REVIEW_TODO_REGISTER.md`",
    "`docs/CLAIMS_GATE_POLICY.md`",
    "`cargo run -p tidefs-xtask -- check-claims-gate`",
];

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
        rule: "tidefsctl command classification must keep public operator commands, userspace harnesses, diagnostics, prototypes, development exercises, and removed surfaces in separate checked buckets; cluster placement/heal exercises and cluster pool prototypes are not final distributed operator UAPI.",
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
        .chain(["xtask/tidefs-xtask/src/claims.rs"])
    {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/claims.rs",
        &[
            "CLAIMS_GATE_POLICY_SPEC",
            "CLAIMS_GATE_REQUIRED_COMMAND",
            "CLAIMS_GATE_SCANNED_DOCS",
            "CLAIMS_GATE_SENSITIVE_PATTERNS",
            "ClaimGateRuleTopic",
            "ClaimGateRule",
            "CLAIMS_GATE_RULES",
            "GitHub issue and pull request state",
            "unreleased authority boundary",
            "mounted transform authority",
            "operator command classification",
            "MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY",
            "claims_gate_policy_covers_current_claim_boundaries",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/CLAIMS_GATE_POLICY.md",
        &[
            "tracked GitHub issue",
            "apps/README.md",
            "crates/README.md",
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
            "`cluster placement\nexercise`",
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
    use super::{
        claims_gate_rules, line_has_present_tense_overclaim, ClaimGateRuleTopic,
        APP_INDEX_LIMITATION_MARKERS, CLAIMS_GATE_POLICY_SPEC, CLAIMS_GATE_REQUIRED_COMMAND,
        CLAIMS_GATE_SCANNED_DOCS, CRATE_INDEX_LIMITATION_MARKERS,
    };

    #[test]
    fn claims_gate_policy_covers_current_claim_boundaries() {
        let rules = claims_gate_rules();
        assert_eq!(rules.len(), 8);

        for topic in [
            ClaimGateRuleTopic::ScannedPublishingSurfaces,
            ClaimGateRuleTopic::ForbiddenCurrentCapabilityClaims,
            ClaimGateRuleTopic::RequiredLimitationMarkers,
            ClaimGateRuleTopic::WorkStateAuthority,
            ClaimGateRuleTopic::UnreleasedAuthority,
            ClaimGateRuleTopic::EvidenceBeforeEscalation,
            ClaimGateRuleTopic::MountedTransformAuthority,
            ClaimGateRuleTopic::OperatorCommandClassification,
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
        assert!(CLAIMS_GATE_SCANNED_DOCS.contains(&"docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md"));
        assert!(CLAIMS_GATE_SCANNED_DOCS
            .contains(&"docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md"));
    }

    #[test]
    fn claims_gate_requires_top_level_index_limitations() {
        for marker in [
            "inventory, not a production-readiness claim",
            "`TFR-011`/`TFR-019` review",
            "storage-node cluster authority remains under `TFR-017`",
            "non-production Local Object Store demo",
        ] {
            assert!(
                APP_INDEX_LIMITATION_MARKERS.contains(&marker),
                "apps index should require marker {marker}"
            );
        }

        for marker in [
            "package counts and tables below are stale",
            "review input, not current package authority",
            "not current package authority",
            "source ownership index, not release proof",
            "Capability claims",
            "must follow `docs/REVIEW_TODO_REGISTER.md`",
            "`cargo run -p tidefs-xtask -- check-claims-gate`",
        ] {
            assert!(
                CRATE_INDEX_LIMITATION_MARKERS.contains(&marker),
                "crates index should require marker {marker}"
            );
        }
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
