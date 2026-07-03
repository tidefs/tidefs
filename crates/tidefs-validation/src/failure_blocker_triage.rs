// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Failure-to-blocker triage for validation failure surfaces.
//!
//! Validation failures must not inherit ownership from historical, deleted
//! planning catalogs. The default triage map therefore contains no static issue
//! numbers. It returns enough surface and claim-gate context for a caller to
//! file or attach a current `tidefs/tidefs` issue, and it fails closed with a
//! `no-live-blocker-mapped` status until a live issue mapping is supplied.

use serde::{Deserialize, Serialize};

const NO_LIVE_BLOCKER_NOTE: &str = "no live GitHub blocker mapped; inspect current tidefs/tidefs issues and validation/claims.toml before treating this failure as owned";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A live GitHub blocker issue that owns one or more validation failure surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerIssue {
    /// GitHub issue number in `tidefs/tidefs`.
    pub issue: u64,
    /// Human-readable issue title.
    pub title: String,
    /// Product or validation domain this blocker belongs to.
    pub domain: BlockerDomain,
    /// Validation tier required to close the blocker.
    pub required_tier: String,
    /// Which live rollup issue or dependency chain this blocker sits under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollup: Option<String>,
}

/// Product or validation domain for live blocker records supplied by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockerDomain {
    FusePosix,
    UblkBlockVolume,
    KernelBlock,
    KernelPosixVfs,
    StorageDurability,
    MultiNodeRdma,
    ValidationInfra,
    ReleaseInfra,
}

impl BlockerDomain {
    pub fn label(&self) -> &'static str {
        match self {
            BlockerDomain::FusePosix => "FUSE POSIX",
            BlockerDomain::UblkBlockVolume => "ublk Block-Volume",
            BlockerDomain::KernelBlock => "Kernel Block",
            BlockerDomain::KernelPosixVfs => "Kernel POSIX VFS",
            BlockerDomain::StorageDurability => "Storage Durability",
            BlockerDomain::MultiNodeRdma => "Multi-Node / RDMA",
            BlockerDomain::ValidationInfra => "Validation Infrastructure",
            BlockerDomain::ReleaseInfra => "Release Infrastructure",
        }
    }
}

/// A concrete failure surface that may map to one or more live blocker issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSurface {
    /// Broad subsystem area, e.g. "fuse-writeback", "ublk-discard".
    pub area: String,
    /// Specific operation or test, e.g. "crash-replay-remount-verify".
    pub operation: String,
    /// Validation tier the failure was observed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Optional keyword fragments that help disambiguate the failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hint: Option<String>,
}

/// Current claim/product-admission context that may own the evidence class for a
/// failure surface. These ids and evidence classes mirror `validation/claims.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimContext {
    pub product_admission_gate: String,
    pub required_evidence_classes: Vec<String>,
    pub authority_paths: Vec<String>,
}

/// Lookup disposition for the current triage result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriageStatus {
    LiveBlockerMapped,
    NoLiveBlockerMapped,
}

/// Outcome of a failure triage lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub surface: FailureSurface,
    /// Matching live blocker issues supplied by the caller.
    pub matched_blockers: Vec<BlockerIssue>,
    /// Current claim/product-admission context inferred from the surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_context: Vec<ClaimContext>,
    /// Fail-closed disposition. `NoLiveBlockerMapped` means no current GitHub
    /// issue owner is known to this triage input.
    pub status: TriageStatus,
    /// Backward-compatible flag for callers that treat unmapped failures as
    /// needing an explicit blocker before validation can be accepted.
    pub needs_new_blocker: bool,
    /// Human-readable fail-closed note for reports and manifests.
    pub note: String,
}

impl TriageResult {
    /// True when at least one live blocker owns this failure surface.
    pub fn has_known_blocker(&self) -> bool {
        !self.matched_blockers.is_empty()
    }

    /// The first matching live blocker issue number, if any.
    pub fn first_blocker_issue(&self) -> Option<u64> {
        self.matched_blockers.first().map(|b| b.issue)
    }

    /// True when no current live blocker was supplied or matched.
    pub fn no_live_blocker_mapped(&self) -> bool {
        self.status == TriageStatus::NoLiveBlockerMapped
    }
}

// ---------------------------------------------------------------------------
// Current claim-gate context
// ---------------------------------------------------------------------------

struct GateSpec {
    id: &'static str,
    keywords: &'static [&'static str],
    required_evidence_classes: &'static [&'static str],
    authority_paths: &'static [&'static str],
}

const GATE_SPECS: &[GateSpec] = &[
    GateSpec {
        id: "local-pool-device-lifecycle",
        keywords: &["pool", "device", "import", "export", "topology", "owner"],
        required_evidence_classes: &[
            "storage-intent-layout-policy-evidence",
            "storage-intent-lifecycle-capacity-evidence",
            "storage-intent-layout-action-execution",
            "local-storage-successor-claim-boundary-review",
            "storage-intent-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/REVIEW_TODO_REGISTER.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "mounted-posix-operator-runtime",
        keywords: &[
            "fuse",
            "posix",
            "mount",
            "namespace",
            "rename",
            "readdir",
            "sticky",
            "nlink",
        ],
        required_evidence_classes: &[
            "fuse-adapter-lifecycle-model",
            "model-crash-matrix",
            "runtime-namespace-crash-artifact",
            "no-hidden-queue-gate",
            "local-storage-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md",
            "docs/OPERATOR_UAPI_AUTHORITY.md",
            "docs/CLAIMS_GATE_POLICY.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "transaction-replay-crash-recovery",
        keywords: &[
            "transaction",
            "replay",
            "crash",
            "fsync",
            "recovery",
            "durability",
        ],
        required_evidence_classes: &[
            "model-crash-matrix",
            "runtime-crash-oracle",
            "runtime-namespace-crash-artifact",
            "storage-intent-ack-fault-matrix",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/REVIEW_TODO_REGISTER.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/RELEASE_READINESS_VERDICT_CONTRACT.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "integrity-scrub-repair-rebuild",
        keywords: &[
            "integrity",
            "scrub",
            "repair",
            "rebuild",
            "checksum",
            "data-shape",
        ],
        required_evidence_classes: &[
            "scrub-read-isolation-model",
            "runtime-scrub-read-artifact",
            "storage-intent-data-shape-policy-evidence",
            "storage-intent-data-shape-performance-fault-rows",
            "distributed-combined-safety-model",
            "distributed-storage-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/SCRUB_IDENTITY_AUTHORITY.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "snapshot-clone-send-receive-reclaim",
        keywords: &[
            "snapshot", "clone", "send", "receive", "reclaim", "deadlist",
        ],
        required_evidence_classes: &[
            "storage-intent-lifecycle-capacity-evidence",
            "storage-intent-layout-action-execution",
            "local-storage-successor-claim-boundary-review",
            "distributed-storage-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/REVIEW_TODO_REGISTER.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "capacity-quota-reserve-accounting",
        keywords: &["capacity", "quota", "reserve", "statfs", "accounting"],
        required_evidence_classes: &[
            "storage-intent-layout-policy-evidence",
            "storage-intent-lifecycle-capacity-evidence",
            "admission-budget-model",
            "queue-depth-runtime-artifact",
            "storage-intent-scheduler-admission-row",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/CAPACITY_ACCOUNTING_AUTHORITY.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/REVIEW_TODO_REGISTER.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "page-cache-writeback-fsync",
        keywords: &[
            "page-cache",
            "writeback",
            "mmap",
            "dirty",
            "invalidate",
            "truncate",
            "hole",
        ],
        required_evidence_classes: &[
            "claims-gate-review",
            "model-crash-matrix",
            "runtime-crash-oracle",
            "admission-budget-model",
            "queue-depth-runtime-artifact",
        ],
        authority_paths: &[
            "docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md",
            "docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md",
            "docs/REVIEW_TODO_REGISTER.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "block-device-product-boundary",
        keywords: &["ublk", "block", "discard", "fua", "flush", "qid", "tag"],
        required_evidence_classes: &[
            "qid-tag-state-model",
            "runtime-ublk-completion-artifact",
            "started-export-service-loop-model",
            "runtime-ublk-started-export-admission-artifact",
            "local-storage-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md",
            "docs/REQUEST_CONTRACT.md",
            "docs/CLAIMS_GATE_POLICY.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "kernel-residency-boundary",
        keywords: &[
            "kernel",
            "kmod",
            "teardown",
            "workqueue",
            "lockdep",
            "kasan",
            "kcsan",
        ],
        required_evidence_classes: &[
            "kernel-context-token-model",
            "teardown-race-proof-artifact",
            "local-storage-successor-claim-boundary-review",
            "storage-intent-successor-claim-boundary-review",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/KERNEL_RESIDENCY_AUTHORITY.md",
            "docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md",
            "docs/GITHUB_CI.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "distributed-product-mode",
        keywords: &[
            "distributed",
            "transport",
            "rdma",
            "cluster",
            "membership",
            "placement",
            "geo",
            "quorum",
            "partition",
        ],
        required_evidence_classes: &[
            "distributed-combined-safety-model",
            "distributed-storage-comparator-equivalence-evidence",
            "distributed-storage-successor-performance-fault-set",
            "storage-intent-geo-policy-transport-evidence",
            "storage-intent-placement-decision-frontier",
            "storage-intent-ack-receipt-runtime",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
            "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
            "docs/REVIEW_TODO_REGISTER.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "operator-uapi-release-verdict",
        keywords: &["operator", "uapi", "release", "verdict", "cli", "tidefsctl"],
        required_evidence_classes: &[
            "local-storage-operator-explanation-evidence",
            "distributed-storage-operator-explanation-evidence",
            "storage-intent-operator-explanation-evidence",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/OPERATOR_UAPI_AUTHORITY.md",
            "docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md",
            "docs/RELEASE_READINESS_VERDICT_CONTRACT.md",
            "docs/CLAIMS_GATE_POLICY.md",
            "validation/claims.toml",
        ],
    },
    GateSpec {
        id: "evidence-proof-train-packet",
        keywords: &[
            "xfstests",
            "qemu",
            "fio",
            "performance",
            "soak",
            "proof",
            "evidence",
        ],
        required_evidence_classes: &[
            "model-crash-matrix",
            "runtime-crash-oracle",
            "runtime-ublk-completion-artifact",
            "teardown-race-proof-artifact",
            "distributed-combined-safety-model",
            "local-storage-successor-performance-fault-set",
            "distributed-storage-successor-performance-fault-set",
            "claims-gate-review",
        ],
        authority_paths: &[
            "docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md",
            "docs/RELEASE_READINESS_VERDICT_CONTRACT.md",
            "docs/GITHUB_CI.md",
            "validation/claims.toml",
        ],
    },
];

// ---------------------------------------------------------------------------
// Triage lookup
// ---------------------------------------------------------------------------

/// Failure blocker triage map.
///
/// `new()` intentionally starts with no issue catalog. Use
/// `with_live_blockers()` when a caller has already resolved current GitHub
/// issue owners for the failure surface.
#[derive(Debug, Clone)]
pub struct FailureBlockerTriage {
    catalog: Vec<BlockerIssue>,
}

impl FailureBlockerTriage {
    /// Build a fail-closed triage map with no static issue numbers.
    pub fn new() -> Self {
        Self {
            catalog: Vec::new(),
        }
    }

    /// Build a triage map from caller-supplied live GitHub blocker issues.
    pub fn with_live_blockers(catalog: Vec<BlockerIssue>) -> Self {
        Self { catalog }
    }

    /// Return the supplied live blocker catalog.
    pub fn catalog(&self) -> &[BlockerIssue] {
        &self.catalog
    }

    /// Number of live blocker issues supplied to this triage map.
    pub fn len(&self) -> usize {
        self.catalog.len()
    }

    /// True when no live blocker catalog was supplied.
    pub fn is_empty(&self) -> bool {
        self.catalog.is_empty()
    }

    /// Find live blocker issues that match a given failure surface.
    ///
    /// Matching is intentionally best-effort: it can only map issue ownership
    /// from the caller-supplied live catalog. Without that catalog, the result
    /// stays fail-closed and reports claim-gate context only.
    pub fn triage(&self, surface: &FailureSurface) -> TriageResult {
        let mut matched: Vec<BlockerIssue> = self
            .catalog
            .iter()
            .filter(|b| blocker_matches_surface(b, surface))
            .cloned()
            .collect();

        matched.sort_by_key(|b| b.issue);
        matched.dedup_by_key(|b| b.issue);

        let has_live_blocker = !matched.is_empty();
        let status = if has_live_blocker {
            TriageStatus::LiveBlockerMapped
        } else {
            TriageStatus::NoLiveBlockerMapped
        };

        TriageResult {
            surface: surface.clone(),
            matched_blockers: matched,
            claim_context: claim_context_for_surface(surface),
            status,
            needs_new_blocker: !has_live_blocker,
            note: if has_live_blocker {
                "live GitHub blocker mapped by caller-supplied catalog".to_string()
            } else {
                NO_LIVE_BLOCKER_NOTE.to_string()
            },
        }
    }

    /// Find a supplied live blocker by exact issue number.
    pub fn by_issue(&self, issue: u64) -> Option<&BlockerIssue> {
        self.catalog.iter().find(|b| b.issue == issue)
    }

    /// Return all supplied live blockers in a given domain.
    pub fn by_domain(&self, domain: BlockerDomain) -> Vec<&BlockerIssue> {
        self.catalog.iter().filter(|b| b.domain == domain).collect()
    }
}

impl Default for FailureBlockerTriage {
    fn default() -> Self {
        Self::new()
    }
}

fn blocker_matches_surface(blocker: &BlockerIssue, surface: &FailureSurface) -> bool {
    let title_lower = blocker.title.to_lowercase();
    let domain_label = blocker.domain.label().to_lowercase();
    surface_tokens(surface)
        .iter()
        .any(|token| title_lower.contains(token) || domain_label.contains(token))
}

fn claim_context_for_surface(surface: &FailureSurface) -> Vec<ClaimContext> {
    let text = surface_text(surface);
    GATE_SPECS
        .iter()
        .filter(|spec| spec.keywords.iter().any(|keyword| text.contains(keyword)))
        .map(|spec| ClaimContext {
            product_admission_gate: spec.id.to_string(),
            required_evidence_classes: spec
                .required_evidence_classes
                .iter()
                .map(|s| s.to_string())
                .collect(),
            authority_paths: spec.authority_paths.iter().map(|s| s.to_string()).collect(),
        })
        .collect()
}

fn surface_text(surface: &FailureSurface) -> String {
    [
        Some(surface.area.as_str()),
        Some(surface.operation.as_str()),
        surface.tier.as_deref(),
        surface.error_hint.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase()
}

fn surface_tokens(surface: &FailureSurface) -> Vec<String> {
    surface_text(surface)
        .split(['-', '_', ' ', '/'])
        .filter(|token| token.len() >= 3)
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn triage() -> FailureBlockerTriage {
        FailureBlockerTriage::new()
    }

    fn fuse_writeback_surface() -> FailureSurface {
        FailureSurface {
            area: "fuse-writeback".into(),
            operation: "direct-io-cache-conflict".into(),
            tier: Some("mounted-userspace".into()),
            error_hint: Some("direct I/O writeback cache conflict".into()),
        }
    }

    #[test]
    fn default_catalog_is_empty() {
        let t = triage();
        assert!(t.is_empty(), "default triage must not embed issue numbers");
        assert_eq!(t.len(), 0);
        assert!(t.catalog().is_empty());
    }

    #[test]
    fn default_triage_fails_closed_without_live_blocker() {
        let t = triage();
        let result = t.triage(&fuse_writeback_surface());

        assert!(!result.has_known_blocker());
        assert_eq!(result.first_blocker_issue(), None);
        assert_eq!(result.status, TriageStatus::NoLiveBlockerMapped);
        assert!(result.no_live_blocker_mapped());
        assert!(result.needs_new_blocker);
        assert!(result.note.contains("no live GitHub blocker mapped"));
    }

    #[test]
    fn fuse_writeback_surface_reports_current_claim_context() {
        let t = triage();
        let result = t.triage(&fuse_writeback_surface());
        let gates: Vec<&str> = result
            .claim_context
            .iter()
            .map(|ctx| ctx.product_admission_gate.as_str())
            .collect();

        assert!(gates.contains(&"mounted-posix-operator-runtime"));
        assert!(gates.contains(&"page-cache-writeback-fsync"));
        assert!(result.claim_context.iter().any(|ctx| ctx
            .required_evidence_classes
            .iter()
            .any(|class| class == "claims-gate-review")));
    }

    #[test]
    fn unknown_surface_still_needs_explicit_blocker() {
        let t = triage();
        let surface = FailureSurface {
            area: "completely-unknown-area".into(),
            operation: "nonexistent-operation".into(),
            tier: None,
            error_hint: None,
        };
        let result = t.triage(&surface);

        assert_eq!(result.status, TriageStatus::NoLiveBlockerMapped);
        assert!(result.needs_new_blocker);
        assert!(result.matched_blockers.is_empty());
        assert!(result.claim_context.is_empty());
    }

    #[test]
    fn injected_live_catalog_can_map_current_owner() {
        let t = FailureBlockerTriage::with_live_blockers(vec![BlockerIssue {
            issue: 42,
            title: "direct writeback cache conflict runtime owner".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "mounted-userspace".into(),
            rollup: None,
        }]);

        let result = t.triage(&fuse_writeback_surface());
        assert!(result.has_known_blocker());
        assert_eq!(result.first_blocker_issue(), Some(42));
        assert_eq!(result.status, TriageStatus::LiveBlockerMapped);
        assert!(!result.no_live_blocker_mapped());
        assert!(!result.needs_new_blocker);
    }

    #[test]
    fn by_issue_and_domain_only_use_supplied_live_catalog() {
        let t = FailureBlockerTriage::with_live_blockers(vec![BlockerIssue {
            issue: 42,
            title: "transport flow-control runtime owner".into(),
            domain: BlockerDomain::MultiNodeRdma,
            required_tier: "multi-process-distributed".into(),
            rollup: Some("live-rollup".into()),
        }]);

        let blocker = t.by_issue(42).unwrap();
        assert_eq!(blocker.title, "transport flow-control runtime owner");
        assert!(t.by_issue(43).is_none());

        let distributed = t.by_domain(BlockerDomain::MultiNodeRdma);
        assert_eq!(distributed.len(), 1);
        assert!(t.by_domain(BlockerDomain::FusePosix).is_empty());
    }

    #[test]
    fn triage_result_serde_roundtrip_preserves_fail_closed_status() {
        let t = triage();
        let result = t.triage(&fuse_writeback_surface());
        let json = serde_json::to_string(&result).unwrap();
        let roundtripped: TriageResult = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.status, TriageStatus::NoLiveBlockerMapped);
        assert_eq!(result.needs_new_blocker, roundtripped.needs_new_blocker);
        assert_eq!(
            result.matched_blockers.len(),
            roundtripped.matched_blockers.len()
        );
        assert_eq!(result.claim_context.len(), roundtripped.claim_context.len());
    }
}
