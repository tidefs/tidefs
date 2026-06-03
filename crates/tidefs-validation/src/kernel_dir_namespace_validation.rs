//! Kernel directory namespace validation module.
//!
//! Produces tier-classified validation output for kmod-posix-vfs inode_operations
//! directory namespace dispatch (lookup, create, unlink, mkdir, rmdir) exercising
//! the VfsEngine bridge through a kernel VFS mount in Linux 7.0 QEMU. Each
//! operation family is validated with committed-root crash-consistency verification.
//!
//! # Validation tiers exercised
//!
//! | Tier | Meaning |
//! |---|---|
//! | `basic-correctness` | Operation semantics, return values, and errno behavior |
//! | `crash-consistency` | Mid-sequence crash, remount, committed-root state verification |
//! | `orphan-prevention` | Post-unlink/rmdir inode lifecycle and orphan-index correctness |
//! | `cross-dir-coherence` | Cross-directory lookup chains and hard-link namespace coherence |
//!
//! # Operation kinds covered
//!
//! - **Lookup** — dentry lookup and stat across directory levels
//! - **Create** — mknod creating new inodes in target directories
//! - **Unlink** — file removal with link-count drop and namespace update
//! - **Mkdir** — subdirectory creation with parent nlink adjustment
//! - **Rmdir** — empty-directory removal with parent consistency check
//! - **CrossDirLookup** — cross-directory lookup chains verifying namespace
//!   coherence across directory boundary transitions
//!
//! # Workload model
//!
//! A `DirNamespaceWorkload` generates deterministic sequences of create,
//! unlink, mkdir, and rmdir operations with expected post-crash namespace
//! state assertions keyed by committed-root epoch. Crash points are placed
//! after each operation to verify idempotent replay and orphan-index integrity.

use crate::runtime_artifact_source::RuntimeArtifactSource;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------- Directory namespace operation kind -----------------------------

/// Directory namespace operation families exercised by this validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DirNamespaceOp {
    /// Dentry lookup and stat across directory levels.
    Lookup,
    /// Mknod creating new inodes in target directories.
    Create,
    /// Unlink removing a file with link-count drop and namespace update.
    Unlink,
    /// Mkdir creating a subdirectory with parent nlink adjustment.
    Mkdir,
    /// Rmdir removing an empty directory with parent consistency check.
    Rmdir,
    /// Cross-directory lookup chain verifying namespace coherence across
    /// directory boundary transitions.
    CrossDirLookup,
}

impl DirNamespaceOp {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Create => "create",
            Self::Unlink => "unlink",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::CrossDirLookup => "cross-dir-lookup",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Lookup => {
                "Dentry lookup and stat across directory levels verifying inode identity"
            }
            Self::Create => "Mknod creating new inodes in empty and populated directories",
            Self::Unlink => "Unlink removing a file with link-count drop and namespace update",
            Self::Mkdir => "Mkdir creating a subdirectory with parent nlink adjustment",
            Self::Rmdir => "Rmdir removing an empty directory with parent consistency check",
            Self::CrossDirLookup => {
                "Cross-directory lookup chain verifying namespace coherence across boundaries"
            }
        }
    }

    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Create | Self::Unlink | Self::Mkdir | Self::Rmdir
        )
    }

    pub fn is_lookup_family(&self) -> bool {
        matches!(self, Self::Lookup | Self::CrossDirLookup)
    }
}

impl fmt::Display for DirNamespaceOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------- Validation tier -------------------------------------------------

/// Domain-specific validation tier for kernel directory namespace validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DirNamespaceValidationTier {
    /// Basic operation correctness: semantics, return values, and errno behavior.
    BasicCorrectness = 0,
    /// Crash-consistency: mid-sequence crash, remount, committed-root verification.
    CrashConsistency = 1,
    /// Orphan prevention: post-unlink/rmdir inode lifecycle and orphan-index correctness.
    OrphanPrevention = 2,
    /// Cross-directory coherence: lookup chains and hard-link namespace verification.
    CrossDirCoherence = 3,
}

impl DirNamespaceValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BasicCorrectness => "basic-correctness",
            Self::CrashConsistency => "crash-consistency",
            Self::OrphanPrevention => "orphan-prevention",
            Self::CrossDirCoherence => "cross-dir-coherence",
        }
    }

    pub fn is_live_runtime(&self) -> bool {
        matches!(self, Self::CrashConsistency | Self::CrossDirCoherence)
    }

    pub fn is_code_only(&self) -> bool {
        matches!(self, Self::BasicCorrectness | Self::OrphanPrevention)
    }

    /// Map this behavioral tier to the unified [`crate::validation_schema::ValidationTier`].
    /// Behavioral tiers do not encode validation quality; this method returns
    /// a sensible default based on the tier's is_live_runtime / is_code_only
    /// classification. Callers should override when the actual execution
    /// environment is known.
    pub fn to_validation_tier(self) -> crate::validation_schema::ValidationTier {
        if self.is_live_runtime() {
            crate::validation_schema::ValidationTier::MountedKernelVfs
        } else {
            crate::validation_schema::ValidationTier::CargoUnit
        }
    }
}

impl fmt::Display for DirNamespaceValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------- Validation outcome -----------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DirNamespaceOutcome {
    Pass,
    Fail,
    Refusal,
    Blocked,
}

impl DirNamespaceOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for DirNamespaceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Refusal => write!(f, "REFUSAL"),
            Self::Blocked => write!(f, "BLOCKED"),
        }
    }
}

// ---------- Validation row ---------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirNamespaceValidationRow {
    pub name: String,
    pub description: String,
    pub op_kind: DirNamespaceOp,
    pub outcome: DirNamespaceOutcome,
    pub tier: DirNamespaceValidationTier,
    /// Unified validation tier (T0-T7) derived from domain tier.
    pub unified_tier: crate::validation_schema::ValidationTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_issue: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_note: Option<String>,
    /// Concrete artifact source for live-runtime tier Pass classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_source: Option<RuntimeArtifactSource>,
}

impl DirNamespaceValidationRow {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        op_kind: DirNamespaceOp,
        tier: DirNamespaceValidationTier,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            op_kind,
            outcome: DirNamespaceOutcome::Blocked,
            tier,
            unified_tier: tier.to_validation_tier(),
            blocker: None,
            child_issue: None,
            output_note: None,
            artifact_source: None,
        }
    }

    pub fn pass(mut self) -> Self {
        self.outcome = DirNamespaceOutcome::Pass;
        self.blocker = None;
        self
    }

    pub fn fail(mut self, blocker: impl Into<String>) -> Self {
        self.outcome = DirNamespaceOutcome::Fail;
        self.blocker = Some(blocker.into());
        self
    }

    pub fn refuse(mut self, reason: impl Into<String>) -> Self {
        self.outcome = DirNamespaceOutcome::Refusal;
        self.blocker = Some(reason.into());
        self
    }

    pub fn blocked(mut self, reason: impl Into<String>) -> Self {
        self.outcome = DirNamespaceOutcome::Blocked;
        self.blocker = Some(reason.into());
        self
    }

    pub fn with_output(mut self, note: impl Into<String>) -> Self {
        self.output_note = Some(note.into());
        self
    }

    pub fn with_child_issue(mut self, issue: u32) -> Self {
        self.child_issue = Some(issue);
        self
    }

    /// Attach a runtime artifact source proving the workload actually executed.
    pub fn with_artifact(mut self, artifact: RuntimeArtifactSource) -> Self {
        self.artifact_source = Some(artifact);
        self
    }

    /// True when this row is a genuine runtime pass: outcome is Pass, the tier
    /// is live-runtime, and a concrete [`RuntimeArtifactSource`] is attached
    /// proving the workload actually executed.
    ///
    /// Code-only tiers (BasicCorrectness, OrphanPrevention) can pass without
    /// artifact source. Live-runtime tiers (CrashConsistency, CrossDirCoherence)
    /// require a genuine artifact.
    pub fn is_genuine_runtime_pass(&self) -> bool {
        self.outcome.is_pass()
            && self.tier.is_live_runtime()
            && self
                .artifact_source
                .as_ref()
                .map(|a| a.is_genuine())
                .unwrap_or(false)
    }
}

// ---------- Validation report ------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirNamespaceValidationReport {
    pub commit: String,
    pub collected_at: String,
    pub environment: String,
    pub rows: Vec<DirNamespaceValidationRow>,
    pub register_status: DirNamespaceRegisterStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DirNamespaceRegisterStatus {
    Closed,
    Advanced,
    NotApplicable,
}

impl DirNamespaceValidationReport {
    pub fn new(commit: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            commit: commit.into(),
            collected_at: chrono_like_now(),
            environment: environment.into(),
            rows: Vec::new(),
            register_status: DirNamespaceRegisterStatus::NotApplicable,
        }
    }

    /// Build the canonical validation report with 24 rows:
    /// 5 core ops (Lookup, Create, Unlink, Mkdir, Rmdir) x 4 tiers = 20 rows
    /// + 4 edge cases (empty-directory removal, name-collision retry,
    ///   nested path resolution, orphan-index verification)
    pub fn canonical(commit: &str, environment: &str) -> Self {
        let mut report = Self::new(commit, environment);

        // Core ops x tiers: 5 x 4 = 20 rows
        let core_ops = [
            DirNamespaceOp::Lookup,
            DirNamespaceOp::Create,
            DirNamespaceOp::Unlink,
            DirNamespaceOp::Mkdir,
            DirNamespaceOp::Rmdir,
        ];
        let tiers = [
            DirNamespaceValidationTier::BasicCorrectness,
            DirNamespaceValidationTier::CrashConsistency,
            DirNamespaceValidationTier::OrphanPrevention,
            DirNamespaceValidationTier::CrossDirCoherence,
        ];

        for &op in &core_ops {
            for &tier in &tiers {
                let name = format!("{}-{}", op.label(), tier.label());
                let description = format!("{} -- {} tier", op.description(), tier.label());
                report.push_row(DirNamespaceValidationRow::new(name, description, op, tier));
            }
        }

        // Edge case rows
        report.push_row(DirNamespaceValidationRow::new(
            "edge-empty-dir-removal",
            "Rmdir on an empty directory verifies no orphaned dentry remains after parent unlink",
            DirNamespaceOp::Rmdir,
            DirNamespaceValidationTier::OrphanPrevention,
        ));
        report.push_row(DirNamespaceValidationRow::new(
            "edge-name-collision-retry",
            "Create after unlink with same name verifies re-use of freed namespace slot",
            DirNamespaceOp::Create,
            DirNamespaceValidationTier::BasicCorrectness,
        ));
        report.push_row(DirNamespaceValidationRow::new(
            "edge-nested-path-resolution",
            "Cross-dir lookup through deeply nested mkdir chain verifies path walk coherence",
            DirNamespaceOp::CrossDirLookup,
            DirNamespaceValidationTier::CrossDirCoherence,
        ));
        report.push_row(DirNamespaceValidationRow::new(
            "edge-orphan-index-verification",
            "Unlink followed by crash and remount verifies orphan-index correctly tracks freed inode",
            DirNamespaceOp::Unlink,
            DirNamespaceValidationTier::OrphanPrevention,
        ));

        report
    }

    pub fn push_row(&mut self, row: DirNamespaceValidationRow) {
        self.rows.push(row);
        self.recompute_status();
    }

    fn recompute_status(&mut self) {
        let any_pass = self.rows.iter().any(|r| r.outcome.is_pass());
        let any_fail = self.rows.iter().any(|r| r.outcome.is_fail());
        let all_refused_or_blocked = self.rows.iter().all(|r| {
            matches!(
                r.outcome,
                DirNamespaceOutcome::Refusal | DirNamespaceOutcome::Blocked
            )
        });

        if all_refused_or_blocked {
            self.register_status = DirNamespaceRegisterStatus::NotApplicable;
        } else if any_fail {
            self.register_status = DirNamespaceRegisterStatus::Advanced;
        } else if any_pass && !any_fail {
            let has_blocked = self
                .rows
                .iter()
                .any(|r| matches!(r.outcome, DirNamespaceOutcome::Blocked));
            if has_blocked {
                self.register_status = DirNamespaceRegisterStatus::Advanced;
            } else {
                self.register_status = DirNamespaceRegisterStatus::Closed;
            }
        }
    }

    pub fn count_outcome(&self, outcome: DirNamespaceOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    pub fn render_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Kernel Directory Namespace Validation Validation\n\n");
        md.push_str(&format!("- **Commit**: {}\n", self.commit));
        md.push_str(&format!("- **Collected**: {}\n", self.collected_at));
        md.push_str(&format!("- **Environment**: {}\n", self.environment));
        md.push_str(&format!("- **Status**: {:?}\n\n", self.register_status));
        md.push_str("| Row | Op | Tier | Outcome | Blocker |\n");
        md.push_str("|---|---|---|---|---|\n");
        for row in &self.rows {
            let blocker = row.blocker.as_deref().unwrap_or("");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                row.name, row.op_kind, row.tier, row.outcome, blocker
            ));
        }
        let p = self.count_outcome(DirNamespaceOutcome::Pass);
        let f = self.count_outcome(DirNamespaceOutcome::Fail);
        let r = self.count_outcome(DirNamespaceOutcome::Refusal);
        let b = self.count_outcome(DirNamespaceOutcome::Blocked);
        md.push_str(&format!(
            "\n**Summary**: {p} PASS, {f} FAIL, {r} REFUSAL, {b} BLOCKED\n"
        ));
        md
    }

    pub fn to_validation_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

// ---------- Workload model -------------------------------------------------

/// A single step in a deterministic directory namespace mutation sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirNamespaceStep {
    /// Step index (0-based) within the workload.
    pub step: u64,
    /// Directory operation to perform.
    pub op: DirNamespaceOp,
    /// Target directory path for the operation.
    pub target_dir: String,
    /// Entry name to operate on.
    pub entry_name: String,
    /// Expected outcome after this step completes.
    pub expected_outcome: DirNamespaceOutcome,
    /// Whether this is a crash point (commit expected before crash injection).
    pub is_crash_point: bool,
}

/// Deterministic directory namespace workload generating create/unlink/mkdir/rmdir
/// sequences with expected post-crash namespace state assertions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirNamespaceWorkload {
    /// Workload name for identification in validation.
    pub name: String,
    /// Ordered sequence of directory namespace operations.
    pub steps: Vec<DirNamespaceStep>,
    /// Committed-root epoch this workload targets for crash-consistency verification.
    pub target_epoch: u64,
}

impl DirNamespaceWorkload {
    /// Build a canonical deterministic workload exercising all six ops
    /// with crash points at key transitions.
    pub fn canonical() -> Self {
        let steps = vec![
            // Phase 1: create files in root directory
            DirNamespaceStep {
                step: 0,
                op: DirNamespaceOp::Create,
                target_dir: "/".into(),
                entry_name: "file-a".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            DirNamespaceStep {
                step: 1,
                op: DirNamespaceOp::Create,
                target_dir: "/".into(),
                entry_name: "file-b".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            DirNamespaceStep {
                step: 2,
                op: DirNamespaceOp::Lookup,
                target_dir: "/".into(),
                entry_name: "file-a".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            // Crash point A: after create+lookup, before unlink
            DirNamespaceStep {
                step: 3,
                op: DirNamespaceOp::Unlink,
                target_dir: "/".into(),
                entry_name: "file-b".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: true,
            },
            // Phase 2: mkdir and nested operations
            DirNamespaceStep {
                step: 4,
                op: DirNamespaceOp::Mkdir,
                target_dir: "/".into(),
                entry_name: "subdir".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            DirNamespaceStep {
                step: 5,
                op: DirNamespaceOp::Create,
                target_dir: "/subdir".into(),
                entry_name: "nested-file".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            // Crash point B: after mkdir+create-in-subdir
            DirNamespaceStep {
                step: 6,
                op: DirNamespaceOp::CrossDirLookup,
                target_dir: "/subdir".into(),
                entry_name: "nested-file".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: true,
            },
            // Phase 3: rmdir and orphan checks
            DirNamespaceStep {
                step: 7,
                op: DirNamespaceOp::Unlink,
                target_dir: "/subdir".into(),
                entry_name: "nested-file".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            DirNamespaceStep {
                step: 8,
                op: DirNamespaceOp::Rmdir,
                target_dir: "/".into(),
                entry_name: "subdir".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: false,
            },
            // Crash point C: after rmdir, verify orphan-index
            DirNamespaceStep {
                step: 9,
                op: DirNamespaceOp::Lookup,
                target_dir: "/".into(),
                entry_name: "file-a".into(),
                expected_outcome: DirNamespaceOutcome::Pass,
                is_crash_point: true,
            },
        ];

        Self {
            name: "canonical-dir-namespace-workload".into(),
            steps,
            target_epoch: 1,
        }
    }

    /// Return only the steps that are crash points.
    pub fn crash_points(&self) -> Vec<&DirNamespaceStep> {
        self.steps.iter().filter(|s| s.is_crash_point).collect()
    }

    /// Return the expected namespace state at a given step index.
    pub fn expected_entries_at_step(&self, step_idx: u64) -> Vec<String> {
        let mut entries: Vec<String> = Vec::new();
        for s in &self.steps {
            if s.step > step_idx {
                break;
            }
            match s.op {
                DirNamespaceOp::Create | DirNamespaceOp::Mkdir => {
                    entries.push(s.entry_name.clone());
                }
                DirNamespaceOp::Unlink | DirNamespaceOp::Rmdir => {
                    entries.retain(|e| e != &s.entry_name);
                }
                _ => {}
            }
        }
        entries.sort();
        entries
    }
}

// ---------- Helpers --------------------------------------------------------

fn chrono_like_now() -> String {
    "2026-05-18T00:00:00Z".to_string()
}

// ---------- Unit tests -----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DirNamespaceOp -------------------------------------------------

    #[test]
    fn op_labels_are_distinct() {
        let labels: Vec<&str> = [
            DirNamespaceOp::Lookup,
            DirNamespaceOp::Create,
            DirNamespaceOp::Unlink,
            DirNamespaceOp::Mkdir,
            DirNamespaceOp::Rmdir,
            DirNamespaceOp::CrossDirLookup,
        ]
        .iter()
        .map(|k| k.label())
        .collect();
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(labels.len(), sorted.len());
    }

    #[test]
    fn op_descriptions_are_non_empty() {
        for op in &[
            DirNamespaceOp::Lookup,
            DirNamespaceOp::Create,
            DirNamespaceOp::Unlink,
            DirNamespaceOp::Mkdir,
            DirNamespaceOp::Rmdir,
            DirNamespaceOp::CrossDirLookup,
        ] {
            assert!(
                !op.description().is_empty(),
                "op {op:?} has empty description"
            );
        }
    }

    #[test]
    fn is_mutating_classification() {
        assert!(!DirNamespaceOp::Lookup.is_mutating());
        assert!(DirNamespaceOp::Create.is_mutating());
        assert!(DirNamespaceOp::Unlink.is_mutating());
        assert!(DirNamespaceOp::Mkdir.is_mutating());
        assert!(DirNamespaceOp::Rmdir.is_mutating());
        assert!(!DirNamespaceOp::CrossDirLookup.is_mutating());
    }

    #[test]
    fn is_lookup_family_classification() {
        assert!(DirNamespaceOp::Lookup.is_lookup_family());
        assert!(!DirNamespaceOp::Create.is_lookup_family());
        assert!(!DirNamespaceOp::Unlink.is_lookup_family());
        assert!(!DirNamespaceOp::Mkdir.is_lookup_family());
        assert!(!DirNamespaceOp::Rmdir.is_lookup_family());
        assert!(DirNamespaceOp::CrossDirLookup.is_lookup_family());
    }

    // -- DirNamespaceValidationTier ----------------------------------------

    #[test]
    fn tier_labels_are_distinct() {
        let labels: Vec<&str> = [
            DirNamespaceValidationTier::BasicCorrectness,
            DirNamespaceValidationTier::CrashConsistency,
            DirNamespaceValidationTier::OrphanPrevention,
            DirNamespaceValidationTier::CrossDirCoherence,
        ]
        .iter()
        .map(|t| t.label())
        .collect();
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(labels.len(), sorted.len());
    }

    #[test]
    fn tier_is_live_runtime() {
        assert!(!DirNamespaceValidationTier::BasicCorrectness.is_live_runtime());
        assert!(DirNamespaceValidationTier::CrashConsistency.is_live_runtime());
        assert!(!DirNamespaceValidationTier::OrphanPrevention.is_live_runtime());
        assert!(DirNamespaceValidationTier::CrossDirCoherence.is_live_runtime());
    }

    #[test]
    fn tier_is_code_only() {
        assert!(DirNamespaceValidationTier::BasicCorrectness.is_code_only());
        assert!(!DirNamespaceValidationTier::CrashConsistency.is_code_only());
        assert!(DirNamespaceValidationTier::OrphanPrevention.is_code_only());
        assert!(!DirNamespaceValidationTier::CrossDirCoherence.is_code_only());
    }

    #[test]
    fn tier_ordering_reflects_effort() {
        assert!(
            DirNamespaceValidationTier::BasicCorrectness
                < DirNamespaceValidationTier::CrashConsistency
        );
        assert!(
            DirNamespaceValidationTier::CrashConsistency
                < DirNamespaceValidationTier::OrphanPrevention
        );
        assert!(
            DirNamespaceValidationTier::OrphanPrevention
                < DirNamespaceValidationTier::CrossDirCoherence
        );
    }

    // -- DirNamespaceValidationRow -----------------------------------------

    #[test]
    fn row_new_defaults_to_blocked() {
        let row = DirNamespaceValidationRow::new(
            "lookup-stat",
            "stat on root",
            DirNamespaceOp::Lookup,
            DirNamespaceValidationTier::BasicCorrectness,
        );
        assert_eq!(row.outcome, DirNamespaceOutcome::Blocked);
        assert!(row.blocker.is_none());
        assert!(row.child_issue.is_none());
    }

    #[test]
    fn row_pass_clears_blocker() {
        let row = DirNamespaceValidationRow::new(
            "r",
            "d",
            DirNamespaceOp::Lookup,
            DirNamespaceValidationTier::BasicCorrectness,
        )
        .blocked("missing")
        .pass();
        assert_eq!(row.outcome, DirNamespaceOutcome::Pass);
        assert!(row.blocker.is_none());
    }

    #[test]
    fn row_fail_sets_blocker() {
        let row = DirNamespaceValidationRow::new(
            "r",
            "d",
            DirNamespaceOp::Create,
            DirNamespaceValidationTier::CrashConsistency,
        )
        .fail("create returns EIO after crash");
        assert_eq!(row.outcome, DirNamespaceOutcome::Fail);
        assert_eq!(
            row.blocker.as_deref(),
            Some("create returns EIO after crash")
        );
    }

    #[test]
    fn row_refuse_sets_blocker() {
        let row = DirNamespaceValidationRow::new(
            "r",
            "d",
            DirNamespaceOp::Mkdir,
            DirNamespaceValidationTier::CrashConsistency,
        )
        .refuse("/dev/kvm unavailable");
        assert_eq!(row.outcome, DirNamespaceOutcome::Refusal);
        assert_eq!(row.blocker.as_deref(), Some("/dev/kvm unavailable"));
    }

    #[test]
    fn row_blocked_sets_blocker() {
        let row = DirNamespaceValidationRow::new(
            "r",
            "d",
            DirNamespaceOp::Rmdir,
            DirNamespaceValidationTier::CrossDirCoherence,
        )
        .blocked("cross-dir coherence harness not yet integrated");
        assert_eq!(row.outcome, DirNamespaceOutcome::Blocked);
        assert_eq!(
            row.blocker.as_deref(),
            Some("cross-dir coherence harness not yet integrated")
        );
    }

    #[test]
    fn row_with_output_and_child_issue() {
        let row = DirNamespaceValidationRow::new(
            "r",
            "d",
            DirNamespaceOp::Lookup,
            DirNamespaceValidationTier::BasicCorrectness,
        )
        .with_output("lookup returned correct inode")
        .with_child_issue(9999);
        assert_eq!(
            row.output_note.as_deref(),
            Some("lookup returned correct inode")
        );
        assert_eq!(row.child_issue, Some(9999));
    }

    // -- Serialization round-trips ---------------------------------------

    #[test]
    fn dir_namespace_op_serde_roundtrip() {
        for op in &[
            DirNamespaceOp::Lookup,
            DirNamespaceOp::Create,
            DirNamespaceOp::Unlink,
            DirNamespaceOp::Mkdir,
            DirNamespaceOp::Rmdir,
            DirNamespaceOp::CrossDirLookup,
        ] {
            let json = serde_json::to_string(op).unwrap();
            let back: DirNamespaceOp = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back, "roundtrip failed for {op:?}");
        }
    }

    #[test]
    fn tier_serde_roundtrip() {
        for tier in &[
            DirNamespaceValidationTier::BasicCorrectness,
            DirNamespaceValidationTier::CrashConsistency,
            DirNamespaceValidationTier::OrphanPrevention,
            DirNamespaceValidationTier::CrossDirCoherence,
        ] {
            let json = serde_json::to_string(tier).unwrap();
            let back: DirNamespaceValidationTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, back);
        }
    }

    #[test]
    fn outcome_serde_roundtrip() {
        for out in &[
            DirNamespaceOutcome::Pass,
            DirNamespaceOutcome::Fail,
            DirNamespaceOutcome::Refusal,
            DirNamespaceOutcome::Blocked,
        ] {
            let json = serde_json::to_string(out).unwrap();
            let back: DirNamespaceOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*out, back);
        }
    }

    #[test]
    fn row_serde_roundtrip() {
        let row = DirNamespaceValidationRow::new(
            "test-row",
            "serialization roundtrip",
            DirNamespaceOp::Create,
            DirNamespaceValidationTier::BasicCorrectness,
        )
        .pass()
        .with_output("all good");
        let json = serde_json::to_string(&row).unwrap();
        let back: DirNamespaceValidationRow = serde_json::from_str(&json).unwrap();
        assert_eq!(row.name, back.name);
        assert_eq!(row.description, back.description);
        assert_eq!(row.op_kind, back.op_kind);
        assert_eq!(row.outcome, back.outcome);
        assert_eq!(row.tier, back.tier);
        assert_eq!(row.output_note, back.output_note);
    }

    #[test]
    fn workload_step_serde_roundtrip() {
        let step = DirNamespaceStep {
            step: 0,
            op: DirNamespaceOp::Create,
            target_dir: "/".into(),
            entry_name: "f".into(),
            expected_outcome: DirNamespaceOutcome::Pass,
            is_crash_point: false,
        };
        let json = serde_json::to_string(&step).unwrap();
        let back: DirNamespaceStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    // -- Validation report -------------------------------------------------

    #[test]
    fn empty_report_is_not_applicable() {
        let p = DirNamespaceValidationReport::new("abc123", "test env");
        assert_eq!(p.register_status, DirNamespaceRegisterStatus::NotApplicable);
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Pass), 0);
    }

    #[test]
    fn all_pass_closes_register() {
        let mut p = DirNamespaceValidationReport::new("abc", "e");
        p.push_row(
            DirNamespaceValidationRow::new(
                "a",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "b",
                "d",
                DirNamespaceOp::Create,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .pass(),
        );
        assert_eq!(p.register_status, DirNamespaceRegisterStatus::Closed);
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Pass), 2);
    }

    #[test]
    fn mix_pass_blocked_is_advanced() {
        let mut p = DirNamespaceValidationReport::new("abc", "e");
        p.push_row(
            DirNamespaceValidationRow::new(
                "a",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "b",
                "d",
                DirNamespaceOp::Create,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .blocked("no kvm"),
        );
        assert_eq!(p.register_status, DirNamespaceRegisterStatus::Advanced);
    }

    #[test]
    fn any_fail_is_advanced() {
        let mut p = DirNamespaceValidationReport::new("abc", "e");
        p.push_row(
            DirNamespaceValidationRow::new(
                "a",
                "d",
                DirNamespaceOp::Unlink,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .fail("bug"),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "b",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        assert_eq!(p.register_status, DirNamespaceRegisterStatus::Advanced);
    }

    #[test]
    fn all_blocked_is_not_applicable() {
        let mut p = DirNamespaceValidationReport::new("abc", "e");
        p.push_row(
            DirNamespaceValidationRow::new(
                "a",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .blocked("no"),
        );
        assert_eq!(p.register_status, DirNamespaceRegisterStatus::NotApplicable);
    }

    #[test]
    fn count_outcome_works() {
        let mut p = DirNamespaceValidationReport::new("abc", "e");
        p.push_row(
            DirNamespaceValidationRow::new(
                "p1",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "p2",
                "d",
                DirNamespaceOp::Create,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "f1",
                "d",
                DirNamespaceOp::Unlink,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .fail("bug"),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "r1",
                "d",
                DirNamespaceOp::Mkdir,
                DirNamespaceValidationTier::CrashConsistency,
            )
            .refuse("no kvm"),
        );
        p.push_row(
            DirNamespaceValidationRow::new(
                "b1",
                "d",
                DirNamespaceOp::Rmdir,
                DirNamespaceValidationTier::CrossDirCoherence,
            )
            .blocked("no harness"),
        );
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Pass), 2);
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Fail), 1);
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Refusal), 1);
        assert_eq!(p.count_outcome(DirNamespaceOutcome::Blocked), 1);
    }

    #[test]
    fn render_markdown_is_non_empty() {
        let mut p = DirNamespaceValidationReport::new("abc123", "test env");
        p.push_row(
            DirNamespaceValidationRow::new(
                "lookup-pass",
                "stat succeeds",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        let md = p.render_markdown();
        assert!(md.contains("Kernel Directory Namespace"));
        assert!(md.contains("lookup-pass"));
        assert!(md.contains("PASS"));
    }

    #[test]
    fn validation_json_is_valid_json() {
        let mut p = DirNamespaceValidationReport::new("abc123", "test env");
        p.push_row(
            DirNamespaceValidationRow::new(
                "r",
                "d",
                DirNamespaceOp::Lookup,
                DirNamespaceValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        let json = p.to_validation_json();
        let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    // -- Canonical report -----------------------------------------------

    #[test]
    fn canonical_report_has_24_rows() {
        let report = DirNamespaceValidationReport::canonical("abc123", "test env");
        assert_eq!(
            report.rows.len(),
            24,
            "canonical report should have 24 rows (20 core + 4 edge cases)"
        );
    }

    #[test]
    fn canonical_report_all_start_blocked() {
        let report = DirNamespaceValidationReport::canonical("abc123", "test env");
        for row in &report.rows {
            assert_eq!(
                row.outcome,
                DirNamespaceOutcome::Blocked,
                "row '{}' should start Blocked",
                row.name
            );
        }
    }

    #[test]
    fn canonical_report_covers_all_core_ops() {
        let report = DirNamespaceValidationReport::canonical("abc123", "test env");
        let core_ops = [
            DirNamespaceOp::Lookup,
            DirNamespaceOp::Create,
            DirNamespaceOp::Unlink,
            DirNamespaceOp::Mkdir,
            DirNamespaceOp::Rmdir,
        ];
        for &op in &core_ops {
            let count = report.rows.iter().filter(|r| r.op_kind == op).count();
            assert!(
                count >= 4,
                "op {op:?} should appear in at least 4 rows, got {count}"
            );
        }
    }

    #[test]
    fn canonical_report_covers_all_tiers() {
        let report = DirNamespaceValidationReport::canonical("abc123", "test env");
        let tiers = [
            DirNamespaceValidationTier::BasicCorrectness,
            DirNamespaceValidationTier::CrashConsistency,
            DirNamespaceValidationTier::OrphanPrevention,
            DirNamespaceValidationTier::CrossDirCoherence,
        ];
        for &tier in &tiers {
            let count = report.rows.iter().filter(|r| r.tier == tier).count();
            assert!(
                count >= 5,
                "tier {tier:?} should appear in at least 5 rows, got {count}"
            );
        }
    }

    #[test]
    fn canonical_report_includes_edge_cases() {
        let report = DirNamespaceValidationReport::canonical("abc123", "test env");
        let edge_names: Vec<&str> = report
            .rows
            .iter()
            .filter(|r| r.name.starts_with("edge-"))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(edge_names.len(), 4, "should have 4 edge case rows");
        assert!(edge_names.contains(&"edge-empty-dir-removal"));
        assert!(edge_names.contains(&"edge-name-collision-retry"));
        assert!(edge_names.contains(&"edge-nested-path-resolution"));
        assert!(edge_names.contains(&"edge-orphan-index-verification"));
    }

    // -- Workload model -------------------------------------------------

    #[test]
    fn canonical_workload_has_steps() {
        let wl = DirNamespaceWorkload::canonical();
        assert_eq!(wl.steps.len(), 10);
        assert_eq!(wl.name, "canonical-dir-namespace-workload");
        assert_eq!(wl.target_epoch, 1);
    }

    #[test]
    fn canonical_workload_has_three_crash_points() {
        let wl = DirNamespaceWorkload::canonical();
        let crash_pts = wl.crash_points();
        assert_eq!(crash_pts.len(), 3);
        let crash_steps: Vec<u64> = crash_pts.iter().map(|s| s.step).collect();
        assert_eq!(crash_steps, vec![3, 6, 9]);
    }

    #[test]
    fn workload_expected_entries_accumulates() {
        let wl = DirNamespaceWorkload::canonical();
        // After step 1 (create file-a, file-b)
        let entries = wl.expected_entries_at_step(1);
        assert_eq!(entries, vec!["file-a", "file-b"]);

        // After step 3 (unlink file-b) -- file-b removed
        let entries = wl.expected_entries_at_step(3);
        assert_eq!(entries, vec!["file-a"]);

        // After step 5 (mkdir subdir, create nested-file in subdir)
        let entries = wl.expected_entries_at_step(5);
        assert_eq!(entries, vec!["file-a", "nested-file", "subdir"]);

        // After step 8 (unlink nested-file, rmdir subdir) -- subdir and nested-file gone
        let entries = wl.expected_entries_at_step(8);
        assert_eq!(entries, vec!["file-a"]);

        // After all steps (step 9 -- lookup file-a)
        let entries = wl.expected_entries_at_step(9);
        assert_eq!(entries, vec!["file-a"]);
    }

    #[test]
    fn workload_step_count_consistent() {
        let wl = DirNamespaceWorkload::canonical();
        for (i, step) in wl.steps.iter().enumerate() {
            assert_eq!(step.step, i as u64, "step index mismatch at position {i}");
        }
    }

    #[test]
    fn workload_serde_roundtrip() {
        let wl = DirNamespaceWorkload::canonical();
        let json = serde_json::to_string(&wl).unwrap();
        let back: DirNamespaceWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(wl, back);
    }

    #[test]
    fn all_ops_exercised_in_workload() {
        let wl = DirNamespaceWorkload::canonical();
        let ops: Vec<DirNamespaceOp> = wl.steps.iter().map(|s| s.op).collect();
        assert!(ops.contains(&DirNamespaceOp::Create));
        assert!(ops.contains(&DirNamespaceOp::Lookup));
        assert!(ops.contains(&DirNamespaceOp::Unlink));
        assert!(ops.contains(&DirNamespaceOp::Mkdir));
        assert!(ops.contains(&DirNamespaceOp::Rmdir));
        assert!(ops.contains(&DirNamespaceOp::CrossDirLookup));
    }

    // -- Outcome helpers ------------------------------------------------

    #[test]
    fn outcome_is_pass_and_is_fail() {
        assert!(DirNamespaceOutcome::Pass.is_pass());
        assert!(!DirNamespaceOutcome::Pass.is_fail());
        assert!(!DirNamespaceOutcome::Fail.is_pass());
        assert!(DirNamespaceOutcome::Fail.is_fail());
        assert!(!DirNamespaceOutcome::Refusal.is_pass());
        assert!(!DirNamespaceOutcome::Refusal.is_fail());
        assert!(!DirNamespaceOutcome::Blocked.is_pass());
        assert!(!DirNamespaceOutcome::Blocked.is_fail());
    }

    /// Guard test: live-runtime tier Pass rows cannot be classified as a
    /// genuine runtime pass without a concrete [`RuntimeArtifactSource`].
    #[test]
    fn guard_live_runtime_pass_requires_artifact_source() {
        // Live-runtime tier Pass without artifact -> not genuine
        let no_artifact = DirNamespaceValidationRow::new(
            "crash-create",
            "create + crash + remount",
            DirNamespaceOp::Create,
            DirNamespaceValidationTier::CrashConsistency,
        )
        .pass();
        assert!(no_artifact.outcome.is_pass());
        assert!(no_artifact.tier.is_live_runtime());
        assert!(!no_artifact.is_genuine_runtime_pass());

        // Live-runtime tier Pass with genuine artifact -> genuine
        let with_artifact = DirNamespaceValidationRow::new(
            "crash-create-verified",
            "create + crash + remount with validation",
            DirNamespaceOp::Create,
            DirNamespaceValidationTier::CrashConsistency,
        )
        .pass()
        .with_artifact(RuntimeArtifactSource {
            command: "qemu-system-x86_64 ...".into(),
            environment: "Linux 7.0 QEMU guest x86_64".into(),
            commit: "abc123def".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/validation/crash_create.log".into()),
            stderr_path: None,
            workload_ran: true,
        });
        assert!(with_artifact.outcome.is_pass());
        assert!(with_artifact.tier.is_live_runtime());
        assert!(with_artifact.is_genuine_runtime_pass());
    }
}
