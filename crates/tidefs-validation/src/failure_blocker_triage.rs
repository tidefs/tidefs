//! Failure-to-blocker triage: maps validation failure surfaces to the exact
//! Forgejo blocker issues that own them.
//!
//! When a validation command fails, the triage lookup answers: which existing
//! blocker issue owns this failure surface?  If no issue maps, the caller gets
//! back the surface metadata needed to propose a precise candidate.
//!
//! The mapping data is derived from the `docs/FEATURE_MATRIX.md`
//! "Remaining * Blockers" sections, which are the repo-tracked source of truth
//! for first-order blocker-to-surface relationships. This module does not
//! invent new blockers; it encodes the existing documented ones.
//!
//! This lets validation runs answer "what blocks this" without re-parsing
//! markdown tables by hand.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A known blocker issue that owns one or more validation failure surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerIssue {
    /// Forgejo issue number.
    pub issue: u64,
    /// Human-readable issue title (abbreviated).
    pub title: String,
    /// Release domain this blocker belongs to.
    pub domain: BlockerDomain,
    /// Validation tier required to close the blocker.
    pub required_tier: String,
    /// Which rollup or dependency chain this blocker sits under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollup: Option<String>,
}

/// Release domain taxonomy matching FEATURE_MATRIX.md sections.
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

/// A concrete failure surface that maps to one or more blocker issues.
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

/// Outcome of a failure triage lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub surface: FailureSurface,
    /// Matching known blocker issues (empty if no mapping exists).
    pub matched_blockers: Vec<BlockerIssue>,
    /// When true, no known blocker owns this surface; a precise candidate
    /// should be proposed.
    pub needs_new_blocker: bool,
}

impl TriageResult {
    /// True when at least one known blocker owns this failure surface.
    pub fn has_known_blocker(&self) -> bool {
        !self.matched_blockers.is_empty()
    }

    /// The first matching blocker issue number, if any.
    pub fn first_blocker_issue(&self) -> Option<u64> {
        self.matched_blockers.first().map(|b| b.issue)
    }
}

// ---------------------------------------------------------------------------
// Blocker catalog -- derived from docs/FEATURE_MATRIX.md
// ---------------------------------------------------------------------------

/// Build the static catalog of all known blocker issues from
/// `docs/FEATURE_MATRIX.md` "Remaining * Blockers" sections.
fn build_blocker_catalog() -> Vec<BlockerIssue> {
    vec![
        // FUSE POSIX backlog (blocked on #6308)
        BlockerIssue {
            issue: 6416,
            title: "FUSE readdirplus large-directory parity".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6417,
            title: "FUSE xattr ACL and security namespace matrix".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6418,
            title: "FUSE idmapped mount refusal or support contract".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6419,
            title: "FUSE copy_file_range splice and sendfile semantics".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6420,
            title: "FUSE direct I/O plus writeback cache conflict guard".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6421,
            title: "FUSE open-unlink and rename-over-open soak".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6422,
            title: "FUSE lock recovery after daemon restart".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6423,
            title: "FUSE statfs quota and reservation consistency".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6424,
            title: "FUSE mount teardown under blocked writers".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6425,
            title: "FUSE fsx fsstress nightly seed corpus".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6426,
            title: "FUSE mmap coherence with truncate and hole punch".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6427,
            title: "FUSE crash replay after mixed directory and data workload".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6428,
            title: "FUSE operator mount option matrix".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 1 (source/docs)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6429,
            title: "FUSE sparse file and dedup interaction validation".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6430,
            title: "FUSE permission nlink and sticky-bit corner cases".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        BlockerIssue {
            issue: 6431,
            title: "FUSE long-haul product demo soak".into(),
            domain: BlockerDomain::FusePosix,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: Some("#6308".into()),
        },
        // ublk Block-Volume blockers (blocked on #6316)
        BlockerIssue {
            issue: 6309,
            title: "ublk QEMU entrypoint and Linux 7.0 pin".into(),
            domain: BlockerDomain::UblkBlockVolume,
            required_tier: "Tier 3 (QEMU guest)".to_string(),
            rollup: Some("#6316".into()),
        },
        BlockerIssue {
            issue: 6311,
            title: "ublk read/write boundary and short I/O handling".into(),
            domain: BlockerDomain::UblkBlockVolume,
            required_tier: "Tier 3 (QEMU guest)".to_string(),
            rollup: Some("#6316".into()),
        },
        BlockerIssue {
            issue: 6312,
            title: "ublk flush FUA discard zero".into(),
            domain: BlockerDomain::UblkBlockVolume,
            required_tier: "Tier 3 (QEMU guest)".to_string(),
            rollup: Some("#6316".into()),
        },
        BlockerIssue {
            issue: 6313,
            title: "ublk guest filesystem mkfs mount remount".into(),
            domain: BlockerDomain::UblkBlockVolume,
            required_tier: "Tier 3 (QEMU guest)".to_string(),
            rollup: Some("#6316".into()),
        },
        BlockerIssue {
            issue: 6315,
            title: "integrated FUSE+ublk workflow".into(),
            domain: BlockerDomain::UblkBlockVolume,
            required_tier: "Tier 3 (QEMU guest)".to_string(),
            rollup: Some("#6316".into()),
        },
        // Kernel Block backlog (blocked on #6296)
        BlockerIssue {
            issue: 6414,
            title: "Kernel block ext4 xfs btrfs guest filesystem matrix".into(),
            domain: BlockerDomain::KernelBlock,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6296".into()),
        },
        BlockerIssue {
            issue: 6415,
            title: "Kernel block long-haul fio powercut campaign".into(),
            domain: BlockerDomain::KernelBlock,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6296".into()),
        },
        BlockerIssue {
            issue: 6404,
            title: "Kernel block partition table and reread behavior".into(),
            domain: BlockerDomain::KernelBlock,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6296".into()),
        },
        BlockerIssue {
            issue: 6405,
            title: "Kernel block queue-depth saturation and fairness".into(),
            domain: BlockerDomain::KernelBlock,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6296".into()),
        },
        BlockerIssue {
            issue: 6406,
            title: "Kernel block timeout and reset recovery path".into(),
            domain: BlockerDomain::KernelBlock,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6296".into()),
        },
        // Kernel POSIX VFS blockers (blocked on #6358)
        BlockerIssue {
            issue: 6280,
            title: "Crash replay and recovery campaign".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6281,
            title: "Kernel xfstests smoke slice".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6395,
            title: "Kernel lockdep KCSAN KASAN smoke campaign".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6394,
            title: "Kernel memory-pressure reclaim and page invalidation suite".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6385,
            title: "Kernel readdirplus and dcache coherency under rename storm".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6389,
            title: "Kernel sparse file hole punching parity suite".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6393,
            title: "Kernel read-only mount and emergency recovery mode".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6396,
            title: "Kernel crash-loop replay campaign across every mutating inode op".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        BlockerIssue {
            issue: 6384,
            title: "Kernel exportfs file-handle and stable inode generation validation".into(),
            domain: BlockerDomain::KernelPosixVfs,
            required_tier: "Tier 5 (mounted kernel VFS / kernel block I/O)".to_string(),
            rollup: Some("#6358".into()),
        },
        // Storage Durability blockers
        BlockerIssue {
            issue: 5937,
            title: "Reconstructed-without-writeback gap: repair writes not durably committed"
                .into(),
            domain: BlockerDomain::StorageDurability,
            required_tier: "Tier 1 (source/cargo)".to_string(),
            rollup: None,
        },
        // Multi-Node / RDMA blockers
        BlockerIssue {
            issue: 5998,
            title: "Transport flow control not wired".into(),
            domain: BlockerDomain::MultiNodeRdma,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: None,
        },
        BlockerIssue {
            issue: 5999,
            title: "Membership eviction not wired".into(),
            domain: BlockerDomain::MultiNodeRdma,
            required_tier: "Tier 3 (mounted userspace / QEMU guest)".to_string(),
            rollup: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Triage engine
// ---------------------------------------------------------------------------

/// The failure-to-blocker triage map.
///
/// Constructed once from the static catalog; supports lookup by surface area,
/// operation keyword, and issue number.
#[derive(Debug, Clone)]
pub struct FailureBlockerTriage {
    catalog: Vec<BlockerIssue>,
}

impl FailureBlockerTriage {
    /// Build the triage map from the canonical blocker catalog.
    pub fn new() -> Self {
        Self {
            catalog: build_blocker_catalog(),
        }
    }

    /// Return the full blocker catalog (all known blocker issues).
    pub fn catalog(&self) -> &[BlockerIssue] {
        &self.catalog
    }

    /// Number of known blocker issues in the catalog.
    pub fn len(&self) -> usize {
        self.catalog.len()
    }

    /// True when the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.catalog.is_empty()
    }

    /// Find blocker issues that match a given failure surface.
    ///
    /// Matching is based on keyword intersection between the surface's area
    /// and operation fields and the blocker's domain and title.
    /// Returns all matching blockers sorted by issue number.
    pub fn triage(&self, surface: &FailureSurface) -> TriageResult {
        let area_lower = surface.area.to_lowercase();
        let op_lower = surface.operation.to_lowercase();
        let hint_lower = surface.error_hint.as_ref().map(|h| h.to_lowercase());

        let mut matched: Vec<BlockerIssue> = self
            .catalog
            .iter()
            .filter(|b| {
                let title_lower = b.title.to_lowercase();
                let domain_label = b.domain.label().to_lowercase();

                let surface_tokens: Vec<&str> = area_lower
                    .split(['-', '_', ' ', '/'])
                    .chain(op_lower.split(['-', '_', ' ', '/']))
                    .filter(|t| t.len() >= 2)
                    .collect();

                let hint_tokens: Vec<&str> = hint_lower
                    .as_deref()
                    .map(|h| {
                        h.split(['-', '_', ' ', '/'])
                            .filter(|t| t.len() >= 2)
                            .collect()
                    })
                    .unwrap_or_default();

                let all_tokens: Vec<&str> = surface_tokens
                    .iter()
                    .chain(hint_tokens.iter())
                    .copied()
                    .collect();

                all_tokens.iter().any(|token| {
                    title_lower.contains(token) || domain_label.contains(token)
                })
            })
            .cloned()
            .collect();

        matched.sort_by_key(|b| b.issue);
        matched.dedup_by_key(|b| b.issue);

        let needs_new_blocker = matched.is_empty();

        TriageResult {
            surface: surface.clone(),
            matched_blockers: matched,
            needs_new_blocker,
        }
    }

    /// Find a blocker by exact issue number.
    pub fn by_issue(&self, issue: u64) -> Option<&BlockerIssue> {
        self.catalog.iter().find(|b| b.issue == issue)
    }

    /// Return all blockers in a given domain.
    pub fn by_domain(&self, domain: BlockerDomain) -> Vec<&BlockerIssue> {
        self.catalog.iter().filter(|b| b.domain == domain).collect()
    }
}

impl Default for FailureBlockerTriage {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn catalog_is_non_empty() {
        let t = triage();
        assert!(!t.is_empty(), "blocker catalog must contain entries");
        assert!(t.len() > 20, "expected at least 20 known blockers");
    }

    #[test]
    fn triage_fuse_writeback_maps_to_6420() {
        let t = triage();
        let surface = FailureSurface {
            area: "fuse-writeback".into(),
            operation: "direct-io-cache-conflict".into(),
            tier: Some("Tier 3".into()),
            error_hint: Some("direct I/O writeback cache conflict".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        let issues: Vec<u64> = result.matched_blockers.iter().map(|b| b.issue).collect();
        assert!(
            issues.contains(&6420),
            "fuse-writeback direct-io-cache-conflict should map to #6420, got {issues:?}"
        );
    }

    #[test]
    fn triage_fuse_crash_replay_maps_to_6427() {
        let t = triage();
        let surface = FailureSurface {
            area: "fuse-crash-replay".into(),
            operation: "mixed-dir-data-remount-verify".into(),
            tier: Some("Tier 3".into()),
            error_hint: Some("crash replay directory data integrity".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6427),
            "fuse-crash-replay should map to #6427"
        );
    }

    #[test]
    fn triage_ublk_discard_maps_to_6312() {
        let t = triage();
        let surface = FailureSurface {
            area: "ublk-discard".into(),
            operation: "fstrim-guest".into(),
            tier: Some("Tier 3".into()),
            error_hint: Some("flush FUA discard zero".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6312),
            "ublk-discard should map to #6312"
        );
    }

    #[test]
    fn triage_kernel_lockdep_maps_to_6395() {
        let t = triage();
        let surface = FailureSurface {
            area: "kernel-lockdep".into(),
            operation: "kasan-lockdep-concurrent".into(),
            tier: Some("Tier 5".into()),
            error_hint: Some("lockdep KCSAN KASAN".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6395),
            "kernel-lockdep should map to #6395"
        );
    }

    #[test]
    fn triage_kernel_crash_replay_maps_to_6280() {
        let t = triage();
        let surface = FailureSurface {
            area: "kernel-vfs-crash".into(),
            operation: "replay-recovery-campaign".into(),
            tier: Some("Tier 5".into()),
            error_hint: None,
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6280),
            "kernel crash replay should map to #6280"
        );
    }

    #[test]
    fn triage_unknown_surface_returns_needs_new_blocker() {
        let t = triage();
        let surface = FailureSurface {
            area: "completely-unknown-area".into(),
            operation: "nonexistent-operation".into(),
            tier: None,
            error_hint: None,
        };
        let result = t.triage(&surface);
        assert!(result.needs_new_blocker);
        assert!(result.matched_blockers.is_empty());
    }

    #[test]
    fn triage_transport_flow_control_maps_to_5998() {
        let t = triage();
        let surface = FailureSurface {
            area: "transport".into(),
            operation: "flow-control".into(),
            tier: Some("Tier 3".into()),
            error_hint: Some("transport flow control backlog".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 5998),
            "transport flow-control should map to #5998"
        );
    }

    #[test]
    fn triage_membership_eviction_maps_to_5999() {
        let t = triage();
        let surface = FailureSurface {
            area: "membership".into(),
            operation: "eviction".into(),
            tier: Some("Tier 3".into()),
            error_hint: None,
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 5999),
            "membership eviction should map to #5999"
        );
    }

    #[test]
    fn by_issue_returns_correct_blocker() {
        let t = triage();
        let b = t.by_issue(6280).unwrap();
        assert_eq!(b.issue, 6280);
        assert!(b.title.contains("Crash replay"));
    }

    #[test]
    fn by_domain_filters_correctly() {
        let t = triage();
        let fuse = t.by_domain(BlockerDomain::FusePosix);
        assert!(fuse.len() >= 16, "expected 16+ FUSE blockers");
        assert!(fuse.iter().all(|b| b.domain == BlockerDomain::FusePosix));
    }

    #[test]
    fn kernel_posix_vfs_blockers_all_tier5() {
        let t = triage();
        let kvfs = t.by_domain(BlockerDomain::KernelPosixVfs);
        for b in &kvfs {
            assert!(
                b.required_tier.contains("Tier 5"),
                "{} (#{}) should require Tier 5, got {}",
                b.title,
                b.issue,
                b.required_tier
            );
        }
    }

    #[test]
    fn triage_kernel_readdirplus_maps_to_6385() {
        let t = triage();
        let surface = FailureSurface {
            area: "kernel-readdir".into(),
            operation: "readdirplus-dcache-rename".into(),
            tier: Some("Tier 5".into()),
            error_hint: Some("readdirplus dcache coherency rename storm".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6385),
            "kernel readdirplus should map to #6385"
        );
    }

    #[test]
    fn triage_kernel_hole_punch_maps_to_6389() {
        let t = triage();
        let surface = FailureSurface {
            area: "kernel-hole-punch".into(),
            operation: "sparse-extent-accounting".into(),
            tier: Some("Tier 5".into()),
            error_hint: Some("hole punching sparse file".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 6389),
            "kernel hole punch should map to #6389"
        );
    }

    #[test]
    fn triage_repair_reconstructed_maps_to_5937() {
        let t = triage();
        let surface = FailureSurface {
            area: "repair".into(),
            operation: "reconstructed-writeback".into(),
            tier: Some("Tier 1".into()),
            error_hint: Some("Reconstructed without writeback".into()),
        };
        let result = t.triage(&surface);
        assert!(result.has_known_blocker());
        assert!(
            result.matched_blockers.iter().any(|b| b.issue == 5937),
            "repair reconstructed should map to #5937"
        );
    }

    #[test]
    fn triage_result_serde_roundtrip() {
        let t = triage();
        let surface = FailureSurface {
            area: "fuse-mmap".into(),
            operation: "truncate-hole-punch".into(),
            tier: Some("Tier 3".into()),
            error_hint: None,
        };
        let result = t.triage(&surface);
        let json = serde_json::to_string(&result).unwrap();
        let roundtripped: TriageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.needs_new_blocker, roundtripped.needs_new_blocker);
        assert_eq!(
            result.matched_blockers.len(),
            roundtripped.matched_blockers.len()
        );
    }

    #[test]
    fn all_fuse_next_blockers_reference_rollup_6308() {
        let t = triage();
        for b in t.by_domain(BlockerDomain::FusePosix) {
            assert_eq!(
                b.rollup.as_deref(),
                Some("#6308"),
                "FUSE NEXT blocker #{} should have rollup #6308",
                b.issue
            );
        }
    }

    #[test]
    fn all_kvfs_next_blockers_reference_rollup_6358() {
        let t = triage();
        for b in t.by_domain(BlockerDomain::KernelPosixVfs) {
            assert_eq!(
                b.rollup.as_deref(),
                Some("#6358"),
                "KVFS NEXT blocker #{} should have rollup #6358",
                b.issue
            );
        }
    }
}
