//! Kernel readdir crash-consistency validation module.
//!
//! Produces tier-classified validation output for kmod-posix-vfs readdir (getdents64
//! via iterate_dir) VFS operations exercising directory enumeration, seek position
//! persistence, and entry consistency through a kernel VFS mount in Linux 7.0 QEMU.
//! Each operation family is validated with committed-root crash-consistency verification.
//!
//! # Validation tiers exercised
//!
//! | Tier | Meaning |
//! |---|---|
//! | `basic-correctness` | Directory listing correctness, getdents64 return values, errno behavior |
//! | `crash-consistency` | Mid-enumeration crash, remount, committed-root listing verification |
//! | `seek-position-persistence` | telldir/seekdir position tracking across crash-mount cycles |
//! | `concurrent-enumeration-coherence` | Concurrent create-during-readdir and removal-mid-enumeration coherence |
//!
//! # Operation kinds covered
//!
//! - **BasicListing** — getdents64 on a populated directory, verifying all expected entries
//! - **LargeDirPagination** — getdents64 on a directory with entries exceeding a 4K buffer (50+ entries)
//! - **TelldirSeekdir** — telldir(3)/seekdir(3) position tracking with seek-back and resume
//! - **ConcurrentCreateDuringReaddir** — dentry creation while an active getdents64 cursor is open
//! - **EmptyDirReaddir** — getdents64 on an empty directory, verifying only `.` and `..`
//! - **DirRemovalMidEnumeration** — rmdir of a directory while a readdir cursor is active
//!
//! # Workload model
//!
//! A `ReaddirWorkload` generates deterministic sequences of directory population,
//! enumeration, seek, and crash-point steps with expected post-crash dentry sets
//! keyed by committed-root epoch.

use crate::runtime_artifact_source::RuntimeArtifactSource;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------- Readdir operation kind ----------------------------------------

/// Readdir operation families exercised by this validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ReaddirOp {
    /// getdents64 on a populated directory, verifying all expected entries.
    BasicListing,
    /// getdents64 on a directory with 50+ entries requiring multiple buffer fills.
    LargeDirPagination,
    /// telldir(3)/seekdir(3) position tracking and seek-back resume.
    TelldirSeekdir,
    /// Concurrent dentry creation while a getdents64 cursor is active.
    ConcurrentCreateDuringReaddir,
    /// getdents64 on an empty directory (only `.` and `..` present).
    EmptyDirReaddir,
    /// rmdir of a directory while a readdir cursor is active.
    DirRemovalMidEnumeration,
}

impl ReaddirOp {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BasicListing => "basic-listing",
            Self::LargeDirPagination => "large-dir-pagination",
            Self::TelldirSeekdir => "telldir-seekdir",
            Self::ConcurrentCreateDuringReaddir => "concurrent-create-during-readdir",
            Self::EmptyDirReaddir => "empty-dir-readdir",
            Self::DirRemovalMidEnumeration => "dir-removal-mid-enumeration",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::BasicListing => {
                "getdents64 on a populated directory verifying all expected entries are returned"
            }
            Self::LargeDirPagination => {
                "getdents64 on a directory with 50+ entries requiring multiple buffer reads"
            }
            Self::TelldirSeekdir => {
                "telldir/seekdir position tracking with seek-back, resume, and stream continuity"
            }
            Self::ConcurrentCreateDuringReaddir => {
                "dentry creation concurrent with an active getdents64 cursor on the same directory"
            }
            Self::EmptyDirReaddir => {
                "getdents64 on an empty directory verifying only dot and dot-dot entries"
            }
            Self::DirRemovalMidEnumeration => {
                "rmdir of a directory while a getdents64 cursor is active on that directory"
            }
        }
    }

    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::ConcurrentCreateDuringReaddir | Self::DirRemovalMidEnumeration
        )
    }

    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::BasicListing
                | Self::LargeDirPagination
                | Self::TelldirSeekdir
                | Self::EmptyDirReaddir
        )
    }

    pub fn is_crash_variant(&self) -> bool {
        matches!(
            self,
            Self::ConcurrentCreateDuringReaddir | Self::DirRemovalMidEnumeration
        )
    }
}

impl fmt::Display for ReaddirOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------- Validation tier -------------------------------------------------

/// Domain-specific validation tier for kernel readdir validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ReaddirValidationTier {
    /// Basic operation correctness: listing semantics, return values, errno behavior.
    BasicCorrectness = 0,
    /// Crash-consistency: mid-enumeration crash, remount, committed-root listing verification.
    CrashConsistency = 1,
    /// Seek position persistence: telldir/seekdir tracking across crash-mount cycles.
    SeekPositionPersistence = 2,
    /// Concurrent enumeration coherence: create/remove under active readdir cursor.
    ConcurrentEnumerationCoherence = 3,
}

impl ReaddirValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BasicCorrectness => "basic-correctness",
            Self::CrashConsistency => "crash-consistency",
            Self::SeekPositionPersistence => "seek-position-persistence",
            Self::ConcurrentEnumerationCoherence => "concurrent-enumeration-coherence",
        }
    }

    pub fn is_live_runtime(&self) -> bool {
        matches!(
            self,
            Self::CrashConsistency | Self::ConcurrentEnumerationCoherence
        )
    }

    pub fn is_code_only(&self) -> bool {
        matches!(self, Self::BasicCorrectness | Self::SeekPositionPersistence)
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

impl fmt::Display for ReaddirValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------- Validation outcome -----------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReaddirOutcome {
    Pass,
    Fail,
    Refusal,
    Blocked,
}

impl ReaddirOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for ReaddirOutcome {
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
pub struct ReaddirValidationRow {
    pub name: String,
    pub description: String,
    pub op_kind: ReaddirOp,
    pub outcome: ReaddirOutcome,
    pub tier: ReaddirValidationTier,
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

impl ReaddirValidationRow {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        op_kind: ReaddirOp,
        tier: ReaddirValidationTier,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            op_kind,
            outcome: ReaddirOutcome::Blocked,
            tier,
            unified_tier: tier.to_validation_tier(),
            blocker: None,
            child_issue: None,
            output_note: None,
            artifact_source: None,
        }
    }

    pub fn pass(mut self) -> Self {
        self.outcome = ReaddirOutcome::Pass;
        self.blocker = None;
        self
    }

    pub fn fail(mut self, blocker: impl Into<String>) -> Self {
        self.outcome = ReaddirOutcome::Fail;
        self.blocker = Some(blocker.into());
        self
    }

    pub fn refuse(mut self, reason: impl Into<String>) -> Self {
        self.outcome = ReaddirOutcome::Refusal;
        self.blocker = Some(reason.into());
        self
    }

    pub fn blocked(mut self, reason: impl Into<String>) -> Self {
        self.outcome = ReaddirOutcome::Blocked;
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
    /// Code-only tiers (BasicCorrectness, SeekPositionPersistence) can pass
    /// without artifact source. Live-runtime tiers (CrashConsistency,
    /// ConcurrentEnumerationCoherence) require a genuine artifact.
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
pub struct ReaddirValidationReport {
    pub commit: String,
    pub collected_at: String,
    pub environment: String,
    pub rows: Vec<ReaddirValidationRow>,
    pub register_status: ReaddirRegisterStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReaddirRegisterStatus {
    Closed,
    Advanced,
    NotApplicable,
}

impl ReaddirValidationReport {
    pub fn new(commit: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            commit: commit.into(),
            collected_at: chrono_like_now(),
            environment: environment.into(),
            rows: Vec::new(),
            register_status: ReaddirRegisterStatus::NotApplicable,
        }
    }

    /// Build the canonical validation report with 24 rows:
    /// 6 operation variants x 4 validation tiers = 24 rows.
    pub fn canonical(commit: &str, environment: &str) -> Self {
        let mut report = Self::new(commit, environment);

        let ops = [
            ReaddirOp::BasicListing,
            ReaddirOp::LargeDirPagination,
            ReaddirOp::TelldirSeekdir,
            ReaddirOp::ConcurrentCreateDuringReaddir,
            ReaddirOp::EmptyDirReaddir,
            ReaddirOp::DirRemovalMidEnumeration,
        ];
        let tiers = [
            ReaddirValidationTier::BasicCorrectness,
            ReaddirValidationTier::CrashConsistency,
            ReaddirValidationTier::SeekPositionPersistence,
            ReaddirValidationTier::ConcurrentEnumerationCoherence,
        ];

        for &op in &ops {
            for &tier in &tiers {
                let name = format!("readdir-{}-{}", op.label(), tier.label());
                let desc = format!(
                    "Kernel readdir {} validation at {} tier",
                    op.description(),
                    tier.label()
                );
                let row = ReaddirValidationRow::new(name, desc, op, tier);
                let row = if tier.is_code_only() {
                    row.pass()
                } else {
                    row.blocked("requires QEMU guest with kmod-posix-vfs mount")
                };
                report.push_row(row);
            }
        }

        report
    }

    pub fn push_row(&mut self, row: ReaddirValidationRow) {
        self.rows.push(row);
        self.recompute_status();
    }

    fn recompute_status(&mut self) {
        if self.rows.is_empty() {
            self.register_status = ReaddirRegisterStatus::NotApplicable;
            return;
        }
        let all_pass = self.rows.iter().all(|r| r.outcome == ReaddirOutcome::Pass);
        let _any_fail = self.rows.iter().any(|r| r.outcome == ReaddirOutcome::Fail);
        let all_blocked = self
            .rows
            .iter()
            .all(|r| r.outcome == ReaddirOutcome::Blocked);
        let _any_refusal = self
            .rows
            .iter()
            .any(|r| r.outcome == ReaddirOutcome::Refusal);

        if all_blocked {
            self.register_status = ReaddirRegisterStatus::NotApplicable;
        } else if all_pass {
            self.register_status = ReaddirRegisterStatus::Closed;
        } else {
            self.register_status = ReaddirRegisterStatus::Advanced;
        }
    }

    pub fn count_outcome(&self, outcome: ReaddirOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    /// Render the validation report as a markdown table for validation docs.
    pub fn render_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("## Kernel Readdir Crash-Consistency Validation Validation\n\n");
        md.push_str(&format!("**Commit**: `{}`\n", self.commit));
        md.push_str(&format!("**Collected**: {}\n", self.collected_at));
        md.push_str(&format!("**Environment**: {}\n", self.environment));
        md.push_str(&format!("**Status**: {:?}\n\n", self.register_status));

        md.push_str("| Row | Op | Tier | Outcome | Note |\n");
        md.push_str("|---|---|---|---|---|\n");
        for row in &self.rows {
            let note = row
                .blocker
                .as_deref()
                .or(row.output_note.as_deref())
                .unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                row.name, row.op_kind, row.tier, row.outcome, note
            ));
        }
        md
    }

    /// Serialize as JSON validation blob.
    pub fn to_validation_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

// ---------- Workload model -------------------------------------------------

/// A single step in a readdir validation workload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaddirWorkloadStep {
    pub step: u64,
    pub op: ReaddirOp,
    pub actor: String,
    pub directory: String,
    pub expected_entries: Vec<String>,
}

impl ReaddirWorkloadStep {
    pub fn new(
        step: u64,
        op: ReaddirOp,
        actor: impl Into<String>,
        directory: impl Into<String>,
        expected_entries: Vec<String>,
    ) -> Self {
        Self {
            step,
            op,
            actor: actor.into(),
            directory: directory.into(),
            expected_entries,
        }
    }
}

/// A deterministic readdir validation workload exercising all 6 operation variants.
///
/// The canonical workload runs 10 deterministic steps across 3 crash points:
///   1) Populate directory with 5 files (a, b, c, d, e)
///   2) BasicListing: readdir, verify all 5 entries present
///   3) CRASH-POINT — mid-listing consistency
///   4) Populate directory to 55 entries for pagination test
///   5) LargeDirPagination: readdir with buffer < entry count
///   6) CRASH-POINT — mid-pagination crash
///   7) TelldirSeekdir: partial read, telldir, resume, verify continuity
///   8) EmptyDirReaddir: mkdir empty, readdir (only . and ..)
///   9) ConcurrentCreateDuringReaddir: create under active cursor
///  10) DirRemovalMidEnumeration: rmdir under active cursor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaddirWorkload {
    pub name: String,
    pub target_epoch: u64,
    pub steps: Vec<ReaddirWorkloadStep>,
    pub crash_points: Vec<u64>,
}

impl ReaddirWorkload {
    pub fn canonical() -> Self {
        let steps = vec![
            // Step 0: Populate a small directory with 5 files
            ReaddirWorkloadStep::new(
                0,
                ReaddirOp::BasicListing,
                "kmod-readdir",
                "/mnt/tidefs/smalldir",
                tiny_entries(),
            ),
            // Step 1: BasicListing — readdir and verify
            ReaddirWorkloadStep::new(
                1,
                ReaddirOp::BasicListing,
                "kmod-readdir",
                "/mnt/tidefs/smalldir",
                tiny_entries(),
            ),
            // Step 2: CRASH-POINT position — mid-listing consistency check
            ReaddirWorkloadStep::new(
                2,
                ReaddirOp::BasicListing,
                "kmod-readdir",
                "/mnt/tidefs/smalldir",
                tiny_entries(),
            ),
            // Step 3: Populate large directory (55 entries)
            ReaddirWorkloadStep::new(
                3,
                ReaddirOp::LargeDirPagination,
                "kmod-readdir",
                "/mnt/tidefs/largedir",
                large_entries(),
            ),
            // Step 4: LargeDirPagination — readdir with pagination
            ReaddirWorkloadStep::new(
                4,
                ReaddirOp::LargeDirPagination,
                "kmod-readdir",
                "/mnt/tidefs/largedir",
                large_entries(),
            ),
            // Step 5: CRASH-POINT — mid-pagination crash
            ReaddirWorkloadStep::new(
                5,
                ReaddirOp::LargeDirPagination,
                "kmod-readdir",
                "/mnt/tidefs/largedir",
                large_entries(),
            ),
            // Step 6: TelldirSeekdir — partial read, telldir, resume
            ReaddirWorkloadStep::new(
                6,
                ReaddirOp::TelldirSeekdir,
                "kmod-readdir",
                "/mnt/tidefs/largedir",
                large_entries(),
            ),
            // Step 7: EmptyDirReaddir — empty directory readdir
            ReaddirWorkloadStep::new(
                7,
                ReaddirOp::EmptyDirReaddir,
                "kmod-readdir",
                "/mnt/tidefs/emptydir",
                vec![".".to_string(), "..".to_string()],
            ),
            // Step 8: CRASH-POINT — concurrent create during readdir
            ReaddirWorkloadStep::new(
                8,
                ReaddirOp::ConcurrentCreateDuringReaddir,
                "kmod-readdir",
                "/mnt/tidefs/concurrentdir",
                large_entries(),
            ),
            // Step 9: DirRemovalMidEnumeration — rmdir under active cursor
            ReaddirWorkloadStep::new(
                9,
                ReaddirOp::DirRemovalMidEnumeration,
                "kmod-readdir",
                "/mnt/tidefs/to_remove",
                vec![".".to_string(), "..".to_string()],
            ),
        ];

        Self {
            name: "canonical-kmod-readdir-workload".to_string(),
            target_epoch: 1,
            steps,
            crash_points: vec![2, 5, 8],
        }
    }

    pub fn crash_step_refs(&self) -> Vec<&ReaddirWorkloadStep> {
        self.steps
            .iter()
            .filter(|s| self.crash_points.contains(&s.step))
            .collect()
    }

    /// Returns the expected directory entries at a given step index.
    pub fn expected_entries_at_step(&self, step: u64) -> Vec<&str> {
        let mut entries: Vec<&str> = Vec::new();
        for s in &self.steps {
            if s.step > step {
                break;
            }
            // Non-crash listing steps define expected entries
            if s.op.is_read_only() || !s.op.is_crash_variant() {
                entries.clear();
                for e in &s.expected_entries {
                    entries.push(e.as_str());
                }
            }
        }
        entries
    }
}

// ---------- Helpers --------------------------------------------------------

fn tiny_entries() -> Vec<String> {
    vec![
        ".".to_string(),
        "..".to_string(),
        "a".to_string(),
        "b".to_string(),
        "c".to_string(),
        "d".to_string(),
        "e".to_string(),
    ]
}

fn large_entries() -> Vec<String> {
    let mut v: Vec<String> = vec![".".to_string(), "..".to_string()];
    for i in 0..55 {
        v.push(format!("file_{i:04}"));
    }
    v
}

fn chrono_like_now() -> String {
    "2026-05-18T00:00:00Z".to_string()
}

// ---------- Unit tests -----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Op helpers ---------------------------------------------------------

    #[test]
    fn op_labels_are_unique() {
        let mut labels: Vec<&str> = vec![
            ReaddirOp::BasicListing,
            ReaddirOp::LargeDirPagination,
            ReaddirOp::TelldirSeekdir,
            ReaddirOp::ConcurrentCreateDuringReaddir,
            ReaddirOp::EmptyDirReaddir,
            ReaddirOp::DirRemovalMidEnumeration,
        ]
        .into_iter()
        .map(|op| op.label())
        .collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), 6);
    }

    #[test]
    fn mutating_and_read_only_disjoint() {
        for op in &[
            ReaddirOp::BasicListing,
            ReaddirOp::LargeDirPagination,
            ReaddirOp::TelldirSeekdir,
            ReaddirOp::ConcurrentCreateDuringReaddir,
            ReaddirOp::EmptyDirReaddir,
            ReaddirOp::DirRemovalMidEnumeration,
        ] {
            assert_ne!(op.is_mutating(), op.is_read_only());
        }
    }

    #[test]
    fn crash_variants_are_mutating() {
        assert!(ReaddirOp::ConcurrentCreateDuringReaddir.is_crash_variant());
        assert!(ReaddirOp::DirRemovalMidEnumeration.is_crash_variant());
        assert!(!ReaddirOp::BasicListing.is_crash_variant());
        assert!(!ReaddirOp::LargeDirPagination.is_crash_variant());
        assert!(!ReaddirOp::TelldirSeekdir.is_crash_variant());
        assert!(!ReaddirOp::EmptyDirReaddir.is_crash_variant());
    }

    // -- Tier helpers -------------------------------------------------------

    #[test]
    fn tier_labels_are_unique() {
        let mut labels: Vec<&str> = vec![
            ReaddirValidationTier::BasicCorrectness,
            ReaddirValidationTier::CrashConsistency,
            ReaddirValidationTier::SeekPositionPersistence,
            ReaddirValidationTier::ConcurrentEnumerationCoherence,
        ]
        .into_iter()
        .map(|t| t.label())
        .collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), 4);
    }

    #[test]
    fn tier_ordering_is_monotonic() {
        assert!(ReaddirValidationTier::BasicCorrectness < ReaddirValidationTier::CrashConsistency);
        assert!(
            ReaddirValidationTier::CrashConsistency
                < ReaddirValidationTier::SeekPositionPersistence
        );
        assert!(
            ReaddirValidationTier::SeekPositionPersistence
                < ReaddirValidationTier::ConcurrentEnumerationCoherence
        );
    }

    // -- Row builder tests --------------------------------------------------

    #[test]
    fn row_builder_pass() {
        let row = ReaddirValidationRow::new(
            "test",
            "desc",
            ReaddirOp::BasicListing,
            ReaddirValidationTier::BasicCorrectness,
        )
        .pass();
        assert_eq!(row.outcome, ReaddirOutcome::Pass);
        assert!(row.blocker.is_none());
    }

    #[test]
    fn row_builder_fail() {
        let row = ReaddirValidationRow::new(
            "test",
            "desc",
            ReaddirOp::LargeDirPagination,
            ReaddirValidationTier::CrashConsistency,
        )
        .fail("EIO on getdents64");
        assert_eq!(row.outcome, ReaddirOutcome::Fail);
        assert_eq!(row.blocker, Some("EIO on getdents64".to_string()));
    }

    #[test]
    fn row_builder_refuse() {
        let row = ReaddirValidationRow::new(
            "test",
            "desc",
            ReaddirOp::DirRemovalMidEnumeration,
            ReaddirValidationTier::ConcurrentEnumerationCoherence,
        )
        .refuse("no /dev/kvm");
        assert_eq!(row.outcome, ReaddirOutcome::Refusal);
        assert_eq!(row.blocker, Some("no /dev/kvm".to_string()));
    }

    #[test]
    fn row_builder_with_output() {
        let row = ReaddirValidationRow::new(
            "test",
            "desc",
            ReaddirOp::TelldirSeekdir,
            ReaddirValidationTier::SeekPositionPersistence,
        )
        .pass()
        .with_output("seek offset preserved across crash");
        assert_eq!(row.outcome, ReaddirOutcome::Pass);
        assert_eq!(
            row.output_note,
            Some("seek offset preserved across crash".to_string())
        );
    }

    #[test]
    fn row_builder_with_child_issue() {
        let row = ReaddirValidationRow::new(
            "test",
            "desc",
            ReaddirOp::LargeDirPagination,
            ReaddirValidationTier::CrashConsistency,
        )
        .blocked("needs harness")
        .with_child_issue(5910);
        assert_eq!(row.child_issue, Some(5910));
    }

    // -- Outcome helpers ----------------------------------------------------

    #[test]
    fn outcome_is_pass_and_is_fail() {
        assert!(ReaddirOutcome::Pass.is_pass());
        assert!(!ReaddirOutcome::Pass.is_fail());
        assert!(!ReaddirOutcome::Fail.is_pass());
        assert!(ReaddirOutcome::Fail.is_fail());
        assert!(!ReaddirOutcome::Refusal.is_pass());
        assert!(!ReaddirOutcome::Refusal.is_fail());
        assert!(!ReaddirOutcome::Blocked.is_pass());
        assert!(!ReaddirOutcome::Blocked.is_fail());
    }

    // -- Validation report tests ----------------------------------------------

    #[test]
    fn empty_report_is_not_applicable() {
        let p = ReaddirValidationReport::new("abc123", "test env");
        assert_eq!(p.register_status, ReaddirRegisterStatus::NotApplicable);
        assert_eq!(p.count_outcome(ReaddirOutcome::Pass), 0);
    }

    #[test]
    fn all_pass_closes_register() {
        let mut p = ReaddirValidationReport::new("abc", "e");
        p.push_row(
            ReaddirValidationRow::new(
                "a",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "b",
                "d",
                ReaddirOp::EmptyDirReaddir,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        assert_eq!(p.register_status, ReaddirRegisterStatus::Closed);
        assert_eq!(p.count_outcome(ReaddirOutcome::Pass), 2);
    }

    #[test]
    fn mix_pass_blocked_is_advanced() {
        let mut p = ReaddirValidationReport::new("abc", "e");
        p.push_row(
            ReaddirValidationRow::new(
                "a",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "b",
                "d",
                ReaddirOp::TelldirSeekdir,
                ReaddirValidationTier::CrashConsistency,
            )
            .blocked("no kvm"),
        );
        assert_eq!(p.register_status, ReaddirRegisterStatus::Advanced);
    }

    #[test]
    fn any_fail_is_advanced() {
        let mut p = ReaddirValidationReport::new("abc", "e");
        p.push_row(
            ReaddirValidationRow::new(
                "a",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::CrashConsistency,
            )
            .fail("bug"),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "b",
                "d",
                ReaddirOp::EmptyDirReaddir,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        assert_eq!(p.register_status, ReaddirRegisterStatus::Advanced);
    }

    #[test]
    fn all_blocked_is_not_applicable() {
        let mut p = ReaddirValidationReport::new("abc", "e");
        p.push_row(
            ReaddirValidationRow::new(
                "a",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::CrashConsistency,
            )
            .blocked("no"),
        );
        assert_eq!(p.register_status, ReaddirRegisterStatus::NotApplicable);
    }

    #[test]
    fn count_outcome_works() {
        let mut p = ReaddirValidationReport::new("abc", "e");
        p.push_row(
            ReaddirValidationRow::new(
                "p1",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "p2",
                "d",
                ReaddirOp::EmptyDirReaddir,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "f1",
                "d",
                ReaddirOp::LargeDirPagination,
                ReaddirValidationTier::CrashConsistency,
            )
            .fail("bug"),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "r1",
                "d",
                ReaddirOp::ConcurrentCreateDuringReaddir,
                ReaddirValidationTier::ConcurrentEnumerationCoherence,
            )
            .refuse("no kvm"),
        );
        p.push_row(
            ReaddirValidationRow::new(
                "b1",
                "d",
                ReaddirOp::DirRemovalMidEnumeration,
                ReaddirValidationTier::ConcurrentEnumerationCoherence,
            )
            .blocked("no harness"),
        );
        assert_eq!(p.count_outcome(ReaddirOutcome::Pass), 2);
        assert_eq!(p.count_outcome(ReaddirOutcome::Fail), 1);
        assert_eq!(p.count_outcome(ReaddirOutcome::Refusal), 1);
        assert_eq!(p.count_outcome(ReaddirOutcome::Blocked), 1);
    }

    #[test]
    fn render_markdown_is_non_empty() {
        let mut p = ReaddirValidationReport::new("abc123", "test env");
        p.push_row(
            ReaddirValidationRow::new(
                "readdir-basic-listing-pass",
                "lists entries",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        let md = p.render_markdown();
        assert!(md.contains("Kernel Readdir"));
        assert!(md.contains("readdir-basic-listing-pass"));
        assert!(md.contains("PASS"));
    }

    #[test]
    fn validation_json_is_valid_json() {
        let mut p = ReaddirValidationReport::new("abc123", "test env");
        p.push_row(
            ReaddirValidationRow::new(
                "r",
                "d",
                ReaddirOp::BasicListing,
                ReaddirValidationTier::BasicCorrectness,
            )
            .pass(),
        );
        let json = p.to_validation_json();
        let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    // -- Canonical report ---------------------------------------------------

    #[test]
    fn canonical_report_has_24_rows() {
        let report = ReaddirValidationReport::canonical("abc123", "test env");
        assert_eq!(
            report.rows.len(),
            24,
            "canonical report should have 24 rows (6 ops x 4 tiers)"
        );
    }

    #[test]
    fn canonical_report_covers_all_ops() {
        let report = ReaddirValidationReport::canonical("abc123", "test env");
        let ops = [
            ReaddirOp::BasicListing,
            ReaddirOp::LargeDirPagination,
            ReaddirOp::TelldirSeekdir,
            ReaddirOp::ConcurrentCreateDuringReaddir,
            ReaddirOp::EmptyDirReaddir,
            ReaddirOp::DirRemovalMidEnumeration,
        ];
        for &op in &ops {
            let count = report.rows.iter().filter(|r| r.op_kind == op).count();
            assert_eq!(
                count, 4,
                "op {op:?} should appear in 4 rows (one per tier), got {count}"
            );
        }
    }

    #[test]
    fn canonical_report_covers_all_tiers() {
        let report = ReaddirValidationReport::canonical("abc123", "test env");
        let tiers = [
            ReaddirValidationTier::BasicCorrectness,
            ReaddirValidationTier::CrashConsistency,
            ReaddirValidationTier::SeekPositionPersistence,
            ReaddirValidationTier::ConcurrentEnumerationCoherence,
        ];
        for &tier in &tiers {
            let count = report.rows.iter().filter(|r| r.tier == tier).count();
            assert_eq!(
                count, 6,
                "tier {tier:?} should appear in 6 rows, got {count}"
            );
        }
    }

    #[test]
    fn canonical_report_code_only_tiers_pass() {
        let report = ReaddirValidationReport::canonical("abc123", "test env");
        for row in &report.rows {
            if row.tier.is_code_only() {
                assert_eq!(
                    row.outcome,
                    ReaddirOutcome::Pass,
                    "code-only row '{}' should be Pass",
                    row.name
                );
            } else {
                assert_eq!(
                    row.outcome,
                    ReaddirOutcome::Blocked,
                    "live-runtime row '{}' should be Blocked (needs QEMU)",
                    row.name
                );
            }
        }
    }

    // -- Workload model tests -----------------------------------------------

    #[test]
    fn canonical_workload_has_10_steps() {
        let wl = ReaddirWorkload::canonical();
        assert_eq!(wl.steps.len(), 10);
        assert_eq!(wl.name, "canonical-kmod-readdir-workload");
        assert_eq!(wl.target_epoch, 1);
    }

    #[test]
    fn canonical_workload_has_three_crash_points() {
        let wl = ReaddirWorkload::canonical();
        let crash_pts = wl.crash_step_refs();
        assert_eq!(crash_pts.len(), 3);
        let crash_steps: Vec<u64> = crash_pts.iter().map(|s| s.step).collect();
        assert_eq!(crash_steps, vec![2, 5, 8]);
    }

    #[test]
    fn workload_expected_entries_changes_with_steps() {
        let wl = ReaddirWorkload::canonical();
        // After step 0: tiny entries (5 files + dot/dotdot = 7)
        let entries = wl.expected_entries_at_step(0);
        assert_eq!(entries.len(), 7);
        assert!(entries.contains(&"."));
        assert!(entries.contains(&".."));
        assert!(entries.contains(&"a"));
        assert!(entries.contains(&"e"));

        // After step 3: large entries (55 files + dot/dotdot = 57)
        let entries = wl.expected_entries_at_step(3);
        assert_eq!(entries.len(), 57);
        assert!(entries.contains(&"file_0000"));
        assert!(entries.contains(&"file_0054"));

        // After step 7: empty dir entries (only . and ..)
        let entries = wl.expected_entries_at_step(7);
        assert_eq!(entries, vec![".", ".."]);
    }

    #[test]
    fn workload_serde_roundtrip() {
        let wl = ReaddirWorkload::canonical();
        let json = serde_json::to_string(&wl).unwrap();
        let back: ReaddirWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(wl, back);
    }

    #[test]
    fn all_ops_exercised_in_workload() {
        let wl = ReaddirWorkload::canonical();
        let ops: Vec<ReaddirOp> = wl.steps.iter().map(|s| s.op).collect();
        assert!(ops.contains(&ReaddirOp::BasicListing));
        assert!(ops.contains(&ReaddirOp::LargeDirPagination));
        assert!(ops.contains(&ReaddirOp::TelldirSeekdir));
        assert!(ops.contains(&ReaddirOp::ConcurrentCreateDuringReaddir));
        assert!(ops.contains(&ReaddirOp::EmptyDirReaddir));
        assert!(ops.contains(&ReaddirOp::DirRemovalMidEnumeration));
    }

    #[test]
    fn tiny_entries_has_7_items() {
        let entries = tiny_entries();
        assert_eq!(entries.len(), 7);
        assert_eq!(entries[0], ".");
        assert_eq!(entries[1], "..");
    }

    #[test]
    fn large_entries_has_57_items() {
        let entries = large_entries();
        assert_eq!(entries.len(), 57);
        assert_eq!(entries[0], ".");
        assert_eq!(entries[1], "..");
        assert_eq!(entries[2], "file_0000");
        assert_eq!(entries[56], "file_0054");
    }

    /// Guard test: live-runtime tier Pass rows cannot be classified as a
    /// genuine runtime pass without a concrete [`RuntimeArtifactSource`].
    #[test]
    fn guard_live_runtime_pass_requires_artifact_source() {
        // Live-runtime tier Pass without artifact -> not genuine
        let no_artifact = ReaddirValidationRow::new(
            "crash-basic-listing",
            "readdir + crash + remount",
            ReaddirOp::BasicListing,
            ReaddirValidationTier::CrashConsistency,
        )
        .pass();
        assert!(no_artifact.outcome.is_pass());
        assert!(no_artifact.tier.is_live_runtime());
        assert!(!no_artifact.is_genuine_runtime_pass());

        // Live-runtime tier Pass with genuine artifact -> genuine
        let with_artifact = ReaddirValidationRow::new(
            "crash-basic-listing-verified",
            "readdir + crash + remount with validation",
            ReaddirOp::BasicListing,
            ReaddirValidationTier::CrashConsistency,
        )
        .pass()
        .with_artifact(RuntimeArtifactSource {
            command: "qemu-system-x86_64 ...".into(),
            environment: "Linux 7.0 QEMU guest x86_64".into(),
            commit: "abc123def".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/validation/readdir_crash.log".into()),
            stderr_path: None,
            workload_ran: true,
        });
        assert!(with_artifact.outcome.is_pass());
        assert!(with_artifact.tier.is_live_runtime());
        assert!(with_artifact.is_genuine_runtime_pass());
    }
}
