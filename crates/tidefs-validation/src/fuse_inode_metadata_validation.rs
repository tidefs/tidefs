// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE inode metadata crash-consistency validation.
//!
//! Produces tier-classified validation output for FUSE userspace inode
//! attribute operations (getattr, setattr with size/mode/owner/timestamps,
//! stat, chmod, chown, utimens). Mounted runtime logs may advance clean and
//! post-crash readback rows; rows without matching runtime evidence remain
//! explicitly blocked or refused.
//!
//! FUSE getattr and setattr handlers are implemented with intent-log crash
//! safety. This module produces the validation output rows exercising the
//! FUSE path through tidefs-fuser, the posix-filesystem-adapter-daemon,
//! and VfsEngine dispatch for inode metadata operations — a surface not
//! covered by existing data-path (read/write), writeback-cache, extent
//! mutation, directory namespace, or file-locking FUSE validation.
//!
//! ## Validation tiers
//!
//! | Tier | Meaning |
//! |---|---|
//! | `CleanRoundTrip` | Clean getattr/setattr round-trip without crashes |
//! | `CrashDuringMutation` | Crash dispatched mid-setattr; verify state |
//! | `PostCrashReadback` | Remount after crash; verify attribute readback |
//! | `CommittedRootVerify` | Verify committed-root hash chain across crash |
//!
//! ## Canonical row set
//!
//! 8 operation types x 4 tiers = 32 validation rows.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Attribute operation kind ──────────────────────────────────────────────

/// FUSE inode attribute operation kind exercised by this validation.
///
/// Covers the FUSE userspace path through tidefs-fuser, the posix-filesystem-
/// adapter-daemon, and VfsEngine dispatch for inode metadata operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum AttrOp {
    /// getattr: retrieve inode attributes (size, mode, uid, gid, timestamps).
    Getattr,
    /// setattr: change file size.
    SetattrSize,
    /// setattr: change file mode (permissions).
    SetattrMode,
    /// setattr: change owner (uid/gid).
    SetattrOwner,
    /// setattr: change timestamps (atime/mtime).
    SetattrTimestamps,
    /// chmod: change mode via dedicated syscall path.
    Chmod,
    /// chown: change owner via dedicated syscall path.
    Chown,
    /// utimens: set timestamps via dedicated syscall path.
    Utimens,
}

impl AttrOp {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Getattr => "getattr",
            Self::SetattrSize => "setattr-size",
            Self::SetattrMode => "setattr-mode",
            Self::SetattrOwner => "setattr-owner",
            Self::SetattrTimestamps => "setattr-timestamps",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Utimens => "utimens",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Getattr => "FUSE getattr: retrieve inode attributes through FUSE getattr handler",
            Self::SetattrSize => "FUSE setattr: change file size through FUSE setattr handler",
            Self::SetattrMode => {
                "FUSE setattr: change file mode/permissions through FUSE setattr handler"
            }
            Self::SetattrOwner => {
                "FUSE setattr: change uid/gid ownership through FUSE setattr handler"
            }
            Self::SetattrTimestamps => {
                "FUSE setattr: change atime/mtime timestamps through FUSE setattr handler"
            }
            Self::Chmod => "FUSE chmod: change mode via chmod syscall dispatch",
            Self::Chown => "FUSE chown: change ownership via chown syscall dispatch",
            Self::Utimens => "FUSE utimens: set timestamps via utimens syscall dispatch",
        }
    }
}

impl fmt::Display for AttrOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Validation tier ─────────────────────────────────────────────────────────

/// Validation tier exercised for FUSE inode metadata validation.
///
/// Four tiers map clean getattr/setattr round-trip → crash-during-mutation
/// → post-crash readback → committed-root hash-chain verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum AttrValidationTier {
    /// Clean round-trip: attribute set + get without simulated crash.
    CleanRoundTrip = 0,
    /// Crash dispatched mid-setattr; verify attribute state.
    CrashDuringMutation = 1,
    /// Remount after crash; verify attribute readback.
    PostCrashReadback = 2,
    /// Verify committed-root hash chain across crash-mount cycle.
    CommittedRootVerify = 3,
}

impl AttrValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::CleanRoundTrip => "clean-round-trip",
            Self::CrashDuringMutation => "crash-during-mutation",
            Self::PostCrashReadback => "post-crash-readback",
            Self::CommittedRootVerify => "committed-root-verify",
        }
    }

    pub fn is_live_runtime(&self) -> bool {
        matches!(
            self,
            Self::CleanRoundTrip | Self::CrashDuringMutation | Self::PostCrashReadback
        )
    }

    pub fn is_code_only(&self) -> bool {
        matches!(self, Self::CommittedRootVerify)
    }
    /// Map this behavioral tier to the unified [`crate::validation_schema::ValidationTier`].
    /// Behavioral tiers do not encode validation quality; this method returns
    /// a sensible default. Callers should override when the execution
    /// environment is known.
    pub fn to_validation_tier(self) -> crate::validation_schema::ValidationTier {
        if self.is_live_runtime() {
            crate::validation_schema::ValidationTier::MountedUserspace
        } else {
            crate::validation_schema::ValidationTier::CargoUnit
        }
    }
}

impl fmt::Display for AttrValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Validation outcome ──────────────────────────────────────────────────────

/// Outcome of a single validation row.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttrOutcome {
    /// Operation behaved correctly at this tier.
    Pass,
    /// Operation produced incorrect behavior at this tier.
    Fail,
    /// Tier cannot be exercised due to environment constraints.
    Refusal,
    /// Tier blocked by missing implementation dependency.
    Blocked,
}

impl AttrOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for AttrOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Refusal => write!(f, "REFUSAL"),
            Self::Blocked => write!(f, "BLOCKED"),
        }
    }
}

// ── Validation row ──────────────────────────────────────────────────────────

/// Single FUSE inode metadata validation row with full disclosure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttrMetadataValidationRow {
    /// Stable short name.
    pub name: String,
    /// Human-readable description of the exercised behaviour.
    pub description: String,
    /// FUSE attribute operation kind.
    pub op_kind: AttrOp,
    /// PASS, FAIL, REFUSAL, or BLOCKED.
    pub outcome: AttrOutcome,
    /// Validation tier achieved.
    pub tier: AttrValidationTier,
    /// Unified validation tier (T0-T7) derived from domain tier.
    pub unified_tier: crate::validation_schema::ValidationTier,
    /// When not PASS: concrete blocker description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    /// Optional implementation issue reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_issue: Option<u32>,
    /// Raw observation from the workload run (truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_note: Option<String>,
}

impl AttrMetadataValidationRow {
    /// Create a new row starting BLOCKED.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        op_kind: AttrOp,
        tier: AttrValidationTier,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            op_kind,
            outcome: AttrOutcome::Blocked,
            tier,
            unified_tier: tier.to_validation_tier(),
            blocker: None,
            child_issue: None,
            output_note: None,
        }
    }

    /// Record a pass.
    pub fn pass(mut self) -> Self {
        self.outcome = AttrOutcome::Pass;
        self.blocker = None;
        self
    }

    /// Record a failure with a blocker description.
    pub fn fail(mut self, blocker: impl Into<String>) -> Self {
        self.outcome = AttrOutcome::Fail;
        self.blocker = Some(blocker.into());
        self
    }

    /// Record an environment refusal.
    pub fn refuse(mut self, reason: impl Into<String>) -> Self {
        self.outcome = AttrOutcome::Refusal;
        self.blocker = Some(reason.into());
        self
    }

    /// Record a blocked row with dependency.
    pub fn blocked(mut self, reason: impl Into<String>) -> Self {
        self.outcome = AttrOutcome::Blocked;
        self.blocker = Some(reason.into());
        self
    }
}

// ── Validation report ───────────────────────────────────────────────────────

/// Full FUSE inode metadata validation report.
///
/// Carries tier-classified validation rows for the FUSE inode metadata
/// release gate, including commit identity, environment disclosure, and
/// canonical row assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttrMetadataValidationReport {
    /// Commit SHA the validation was collected against.
    pub commit: String,
    /// Validation collection timestamp (ISO 8601).
    pub collected_at: String,
    /// Environment description (host kernel, FUSE availability, backend).
    pub environment: String,
    /// Artifact or workflow scope that produced or owns the row observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_scope: Option<String>,
    /// Individual validation rows.
    pub rows: Vec<AttrMetadataValidationRow>,
    /// Register status after this validation collection.
    pub register_status: AttrMetadataRegisterStatus,
}

/// Summary of row observations applied from a mounted runtime log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttrMetadataRuntimeApplySummary {
    pub observed_rows: usize,
    pub ignored_lines: usize,
    pub pass: usize,
    pub fail: usize,
    pub refusal: usize,
    pub blocked: usize,
}

impl AttrMetadataRuntimeApplySummary {
    fn record(&mut self, outcome: AttrOutcome) {
        self.observed_rows += 1;
        match outcome {
            AttrOutcome::Pass => self.pass += 1,
            AttrOutcome::Fail => self.fail += 1,
            AttrOutcome::Refusal => self.refusal += 1,
            AttrOutcome::Blocked => self.blocked += 1,
        }
    }
}

/// What this validation implies for the FUSE inode metadata register entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttrMetadataRegisterStatus {
    /// All needed validation collected; register entry resolved.
    Closed,
    /// Some rows advanced; others remain.
    Advanced,
    /// No live rows could be exercised.
    NotApplicable,
}

// ── Canonical row builder ─────────────────────────────────────────────────

/// Build the canonical 32-row validation set (8 operations x 4 tiers).
///
/// Rows cover:
/// - getattr: attribute retrieval correctness
/// - setattr-size: size change persistence
/// - setattr-mode: mode/permission persistence
/// - setattr-owner: uid/gid ownership persistence
/// - setattr-timestamps: atime/mtime persistence
/// - chmod: mode change via dedicated syscall path
/// - chown: ownership change via dedicated syscall path
/// - utimens: timestamp set via dedicated syscall path
///
/// Each operation exercises four tiers: clean round-trip, crash-during-
/// mutation, post-crash readback, and committed-root verification.
pub fn canonical_fuse_inode_metadata_rows() -> Vec<AttrMetadataValidationRow> {
    let mut rows = Vec::with_capacity(32);

    let ops = [
        AttrOp::Getattr,
        AttrOp::SetattrSize,
        AttrOp::SetattrMode,
        AttrOp::SetattrOwner,
        AttrOp::SetattrTimestamps,
        AttrOp::Chmod,
        AttrOp::Chown,
        AttrOp::Utimens,
    ];

    let tiers = [
        AttrValidationTier::CleanRoundTrip,
        AttrValidationTier::CrashDuringMutation,
        AttrValidationTier::PostCrashReadback,
        AttrValidationTier::CommittedRootVerify,
    ];

    let tier_suffixes = ["clean", "crash", "readback", "verify"];

    for &op in &ops {
        for (ti, &tier) in tiers.iter().enumerate() {
            let name = format!("{}-{}", op.label(), tier_suffixes[ti]);
            let desc = format!(
                "{}: {} at {} tier",
                op.label(),
                op.description(),
                tier.label(),
            );
            rows.push(AttrMetadataValidationRow::new(name, desc, op, tier));
        }
    }

    rows
}

// ── Report methods ────────────────────────────────────────────────────────

impl AttrMetadataValidationReport {
    /// Create a report with canonical rows, all BLOCKED at clean-round-trip.
    pub fn new(commit: &str, collected_at: &str, environment: &str) -> Self {
        Self {
            commit: commit.to_string(),
            collected_at: collected_at.to_string(),
            environment: environment.to_string(),
            artifact_scope: None,
            rows: canonical_fuse_inode_metadata_rows(),
            register_status: AttrMetadataRegisterStatus::Advanced,
        }
    }

    /// Create the issue #1770 baseline with every blocked row explained.
    ///
    /// This records the current boundary without converting existing mounted
    /// tests or harness presence into runtime evidence. A mounted runtime log
    /// can then be applied with [`Self::apply_runtime_log`].
    pub fn issue_1770_baseline(
        commit: &str,
        collected_at: &str,
        environment: &str,
        artifact_scope: &str,
    ) -> Self {
        let mut report = Self::new(commit, collected_at, environment);
        report.set_artifact_scope(artifact_scope);
        report.apply_issue_1770_blockers();
        report
    }

    /// Set the report-level artifact scope.
    pub fn set_artifact_scope(&mut self, artifact_scope: impl Into<String>) {
        self.artifact_scope = Some(artifact_scope.into());
    }

    /// Attach explicit blockers for the current issue #1770 boundary.
    pub fn apply_issue_1770_blockers(&mut self) {
        for row in &mut self.rows {
            row.outcome = AttrOutcome::Blocked;
            row.output_note = None;
            row.blocker = Some(match row.tier {
                AttrValidationTier::CleanRoundTrip => match row.op_kind {
                    AttrOp::Getattr => "pending mounted userspace artifact; apps/tidefs-posix-filesystem-adapter-daemon/tests/getattr_stat_smoke.rs can satisfy clean getattr after execution".to_string(),
                    AttrOp::SetattrSize => "pending mounted userspace artifact; crates/tidefs-validation/tests/metadata_ops.rs truncate rows can satisfy clean setattr-size after execution".to_string(),
                    AttrOp::SetattrMode | AttrOp::Chmod => "pending mounted userspace artifact; crates/tidefs-validation/tests/metadata_ops.rs chmod rows can satisfy clean mode metadata after execution".to_string(),
                    AttrOp::SetattrOwner | AttrOp::Chown => "pending mounted userspace artifact; crates/tidefs-validation/tests/metadata_ops.rs chown rows require root-capable mounted execution or an explicit environment refusal".to_string(),
                    AttrOp::SetattrTimestamps | AttrOp::Utimens => "pending mounted userspace artifact; crates/tidefs-validation/tests/metadata_ops.rs utimens rows can satisfy clean timestamp metadata after execution".to_string(),
                },
                AttrValidationTier::CrashDuringMutation => "blocked: no mounted FUSE fault-injection harness currently crashes inside the metadata mutation window for this row".to_string(),
                AttrValidationTier::PostCrashReadback => "pending fuse-inode-metadata-validation runtime artifact; existing crash tests cover selected data/mode rows but not all eight metadata operations until the row lane records readback".to_string(),
                AttrValidationTier::CommittedRootVerify => "blocked: current mounted FUSE inode metadata lane does not verify a committed-root hash chain for this row".to_string(),
            });
        }
    }

    /// Count rows by outcome.
    pub fn count_by_outcome(&self) -> (usize, usize, usize, usize) {
        let (mut pass, mut fail, mut refusal, mut blocked) = (0, 0, 0, 0);
        for row in &self.rows {
            match row.outcome {
                AttrOutcome::Pass => pass += 1,
                AttrOutcome::Fail => fail += 1,
                AttrOutcome::Refusal => refusal += 1,
                AttrOutcome::Blocked => blocked += 1,
            }
        }
        (pass, fail, refusal, blocked)
    }

    /// Count rows by tier.
    pub fn count_by_tier(&self) -> (usize, usize, usize, usize) {
        let (mut clean, mut crash, mut readback, mut verify) = (0, 0, 0, 0);
        for row in &self.rows {
            match row.tier {
                AttrValidationTier::CleanRoundTrip => clean += 1,
                AttrValidationTier::CrashDuringMutation => crash += 1,
                AttrValidationTier::PostCrashReadback => readback += 1,
                AttrValidationTier::CommittedRootVerify => verify += 1,
            }
        }
        (clean, crash, readback, verify)
    }

    /// Update a row by name, returning true if found.
    pub fn update_row(
        &mut self,
        name: &str,
        outcome: AttrOutcome,
        tier: AttrValidationTier,
        blocker: Option<String>,
    ) -> bool {
        for row in &mut self.rows {
            if row.name == name {
                row.outcome = outcome;
                row.tier = tier;
                row.blocker = blocker;
                return true;
            }
        }
        false
    }

    /// Apply row observations emitted by the mounted FUSE metadata lane.
    ///
    /// Accepted lines are of the form `PASS: row-name`,
    /// `FAIL: row-name -- reason`, `REFUSAL: row-name -- reason`, or
    /// `BLOCKED: row-name -- reason`. Non-row harness status lines are ignored.
    pub fn apply_runtime_log(
        &mut self,
        log: &str,
        artifact_scope: &str,
    ) -> AttrMetadataRuntimeApplySummary {
        self.set_artifact_scope(artifact_scope);
        let mut summary = AttrMetadataRuntimeApplySummary::default();

        for line in log.lines() {
            let Some((outcome, row_name, detail)) = parse_runtime_row_line(line) else {
                continue;
            };

            if let Some(row) = self.rows.iter_mut().find(|row| row.name == row_name) {
                row.outcome = outcome;
                row.blocker = match outcome {
                    AttrOutcome::Pass => None,
                    AttrOutcome::Fail | AttrOutcome::Refusal | AttrOutcome::Blocked => {
                        detail.clone()
                    }
                };
                row.output_note = Some(match detail {
                    Some(detail) => format!("{artifact_scope}: {detail}"),
                    None => artifact_scope.to_string(),
                });
                summary.record(outcome);
            } else {
                summary.ignored_lines += 1;
            }
        }

        summary
    }

    /// Apply an outcome to all rows of a given op_kind.
    pub fn apply_to_op_kind(
        &mut self,
        op_kind: AttrOp,
        outcome: AttrOutcome,
        tier: AttrValidationTier,
        blocker: Option<String>,
    ) {
        for row in &mut self.rows {
            if row.op_kind == op_kind {
                row.outcome = outcome;
                row.tier = tier;
                row.blocker = blocker.clone();
            }
        }
    }

    /// Advance all rows to a given validation tier with a given outcome.
    ///
    /// Only advances rows at a lower tier; rows already at a higher tier
    /// retain their existing outcome.
    pub fn advance_all_to_tier(
        &mut self,
        tier: AttrValidationTier,
        outcome: AttrOutcome,
        blocker: Option<&str>,
    ) {
        for row in &mut self.rows {
            if row.tier < tier {
                row.tier = tier;
                row.outcome = outcome;
                row.blocker = blocker.map(|s| s.to_string());
            }
        }
    }

    /// Set the register status.
    pub fn set_register_status(&mut self, status: AttrMetadataRegisterStatus) {
        self.register_status = status;
    }

    /// Count rows at a specific tier.
    pub fn count_at_tier(&self, tier: AttrValidationTier) -> usize {
        self.rows.iter().filter(|r| r.tier == tier).count()
    }

    /// Render the report as a Markdown report.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();

        out.push_str("# TideFS FUSE Inode Metadata Validation Report\n\n");
        out.push_str(&format!(
            "Commit: `{}`  \nCollected: {}  \nEnvironment: {}\n\n",
            self.commit, self.collected_at, self.environment,
        ));
        if let Some(artifact_scope) = &self.artifact_scope {
            out.push_str(&format!("Artifact scope: `{artifact_scope}`\n\n"));
        }

        let (pass, fail, refusal, blocked) = self.count_by_outcome();
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "| PASS | FAIL | REFUSAL | BLOCKED | Total |\n\
             |---|---|---|---|---|\n\
             | {pass} | {fail} | {refusal} | {blocked} | {} |\n\n",
            self.rows.len(),
        ));

        out.push_str("## Validation rows\n\n");
        out.push_str("| Op | Row | Outcome | Tier | Blocker |\n");
        out.push_str("|---|---|---|---|---|\n");
        for r in &self.rows {
            let blocker = r.blocker.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                r.op_kind.label(),
                r.description,
                r.outcome,
                r.tier,
                blocker,
            ));
        }
        out.push('\n');

        out.push_str("## Register status\n\n");
        let status_str = match self.register_status {
            AttrMetadataRegisterStatus::Closed => "**Closed**: all needed validation collected.",
            AttrMetadataRegisterStatus::Advanced => {
                "**Advanced**: partial validation collected; remaining gaps noted above."
            }
            AttrMetadataRegisterStatus::NotApplicable => {
                "**Not applicable**: no live rows could be exercised."
            }
        };
        out.push_str(status_str);
        out.push('\n');

        out
    }
}

fn parse_runtime_row_line(line: &str) -> Option<(AttrOutcome, String, Option<String>)> {
    let line = line.trim();
    let (outcome, rest) = if let Some(rest) = line.strip_prefix("PASS:") {
        (AttrOutcome::Pass, rest)
    } else if let Some(rest) = line.strip_prefix("FAIL:") {
        (AttrOutcome::Fail, rest)
    } else if let Some(rest) = line.strip_prefix("REFUSAL:") {
        (AttrOutcome::Refusal, rest)
    } else if let Some(rest) = line.strip_prefix("BLOCKED:") {
        (AttrOutcome::Blocked, rest)
    } else {
        return None;
    };

    let rest = rest.trim();
    let (row_name, detail) = rest
        .split_once(" -- ")
        .map_or((rest, None), |(name, detail)| {
            let detail = detail.trim();
            (
                name.trim(),
                if detail.is_empty() {
                    None
                } else {
                    Some(detail.to_string())
                },
            )
        });

    if row_name.is_empty() {
        None
    } else {
        Some((outcome, row_name.to_string(), detail))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Schema type tests ──────────────────────────────────────────────

    #[test]
    fn canonical_rows_count_32() {
        let rows = canonical_fuse_inode_metadata_rows();
        assert_eq!(rows.len(), 32, "expected 32 rows (8 ops x 4 tiers)");
    }

    #[test]
    fn canonical_rows_each_op_has_four() {
        let rows = canonical_fuse_inode_metadata_rows();
        let ops = [
            AttrOp::Getattr,
            AttrOp::SetattrSize,
            AttrOp::SetattrMode,
            AttrOp::SetattrOwner,
            AttrOp::SetattrTimestamps,
            AttrOp::Chmod,
            AttrOp::Chown,
            AttrOp::Utimens,
        ];
        for &op in &ops {
            let count = rows.iter().filter(|r| r.op_kind == op).count();
            assert_eq!(count, 4, "op_kind {op:?} has {count} rows, expected 4");
        }
    }

    #[test]
    fn canonical_rows_each_tier_has_eight() {
        let rows = canonical_fuse_inode_metadata_rows();
        let tiers = [
            AttrValidationTier::CleanRoundTrip,
            AttrValidationTier::CrashDuringMutation,
            AttrValidationTier::PostCrashReadback,
            AttrValidationTier::CommittedRootVerify,
        ];
        for &tier in &tiers {
            let count = rows.iter().filter(|r| r.tier == tier).count();
            assert_eq!(count, 8, "tier {tier:?} has {count} rows, expected 8");
        }
    }

    #[test]
    fn canonical_rows_start_blocked() {
        for row in canonical_fuse_inode_metadata_rows() {
            assert_eq!(row.outcome, AttrOutcome::Blocked);
            assert!(row.blocker.is_none(), "fresh row should have no blocker");
        }
    }

    #[test]
    fn canonical_rows_unique_names() {
        use std::collections::HashSet;
        let rows = canonical_fuse_inode_metadata_rows();
        let names: HashSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names.len(),
            rows.len(),
            "all row names must be unique; found {} names for {} rows",
            names.len(),
            rows.len()
        );
    }

    // ── Row builder tests ──────────────────────────────────────────────

    #[test]
    fn row_builder_pass() {
        let row = AttrMetadataValidationRow::new(
            "test-row",
            "test desc",
            AttrOp::Getattr,
            AttrValidationTier::CleanRoundTrip,
        )
        .pass();
        assert_eq!(row.outcome, AttrOutcome::Pass);
        assert!(row.blocker.is_none());
    }

    #[test]
    fn row_builder_fail() {
        let row = AttrMetadataValidationRow::new(
            "x",
            "x",
            AttrOp::Chmod,
            AttrValidationTier::CrashDuringMutation,
        )
        .fail("mode not persisted after crash");
        assert_eq!(row.outcome, AttrOutcome::Fail);
        assert_eq!(
            row.blocker.as_deref(),
            Some("mode not persisted after crash")
        );
    }

    #[test]
    fn row_builder_refuse() {
        let row = AttrMetadataValidationRow::new(
            "x",
            "x",
            AttrOp::Utimens,
            AttrValidationTier::PostCrashReadback,
        )
        .refuse("/dev/fuse not available in this environment");
        assert_eq!(row.outcome, AttrOutcome::Refusal);
        assert_eq!(
            row.blocker.as_deref(),
            Some("/dev/fuse not available in this environment")
        );
    }

    #[test]
    fn row_builder_blocked() {
        let row = AttrMetadataValidationRow::new(
            "x",
            "x",
            AttrOp::SetattrOwner,
            AttrValidationTier::PostCrashReadback,
        )
        .blocked("setattr owner handler not implemented");
        assert_eq!(row.outcome, AttrOutcome::Blocked);
        assert_eq!(
            row.blocker.as_deref(),
            Some("setattr owner handler not implemented")
        );
    }

    // ── AttrOp tests ───────────────────────────────────────────────────

    #[test]
    fn attr_op_labels() {
        assert_eq!(AttrOp::Getattr.label(), "getattr");
        assert_eq!(AttrOp::SetattrSize.label(), "setattr-size");
        assert_eq!(AttrOp::SetattrMode.label(), "setattr-mode");
        assert_eq!(AttrOp::SetattrOwner.label(), "setattr-owner");
        assert_eq!(AttrOp::SetattrTimestamps.label(), "setattr-timestamps");
        assert_eq!(AttrOp::Chmod.label(), "chmod");
        assert_eq!(AttrOp::Chown.label(), "chown");
        assert_eq!(AttrOp::Utimens.label(), "utimens");
    }

    #[test]
    fn attr_op_descriptions_not_empty() {
        let ops = [
            AttrOp::Getattr,
            AttrOp::SetattrSize,
            AttrOp::SetattrMode,
            AttrOp::SetattrOwner,
            AttrOp::SetattrTimestamps,
            AttrOp::Chmod,
            AttrOp::Chown,
            AttrOp::Utimens,
        ];
        for op in &ops {
            assert!(!op.description().is_empty(), "{op:?} description is empty");
        }
    }

    #[test]
    fn attr_op_display_matches_label() {
        for op in &[
            AttrOp::Getattr,
            AttrOp::SetattrSize,
            AttrOp::SetattrMode,
            AttrOp::SetattrOwner,
            AttrOp::SetattrTimestamps,
            AttrOp::Chmod,
            AttrOp::Chown,
            AttrOp::Utimens,
        ] {
            assert_eq!(op.to_string(), op.label());
        }
    }

    // ── Tier tests ─────────────────────────────────────────────────────

    #[test]
    fn tier_labels() {
        assert_eq!(
            AttrValidationTier::CleanRoundTrip.label(),
            "clean-round-trip"
        );
        assert_eq!(
            AttrValidationTier::CrashDuringMutation.label(),
            "crash-during-mutation"
        );
        assert_eq!(
            AttrValidationTier::PostCrashReadback.label(),
            "post-crash-readback"
        );
        assert_eq!(
            AttrValidationTier::CommittedRootVerify.label(),
            "committed-root-verify"
        );
    }

    #[test]
    fn tier_ordering() {
        assert!(AttrValidationTier::CleanRoundTrip < AttrValidationTier::CrashDuringMutation);
        assert!(AttrValidationTier::CrashDuringMutation < AttrValidationTier::PostCrashReadback);
        assert!(AttrValidationTier::PostCrashReadback < AttrValidationTier::CommittedRootVerify);
    }

    #[test]
    fn tier_is_live_runtime() {
        assert!(AttrValidationTier::CleanRoundTrip.is_live_runtime());
        assert!(AttrValidationTier::CrashDuringMutation.is_live_runtime());
        assert!(AttrValidationTier::PostCrashReadback.is_live_runtime());
        assert!(!AttrValidationTier::CommittedRootVerify.is_live_runtime());
    }

    #[test]
    fn tier_display_matches_label() {
        for tier in &[
            AttrValidationTier::CleanRoundTrip,
            AttrValidationTier::CrashDuringMutation,
            AttrValidationTier::PostCrashReadback,
            AttrValidationTier::CommittedRootVerify,
        ] {
            assert_eq!(tier.to_string(), tier.label());
        }
    }

    // ── Outcome tests ──────────────────────────────────────────────────

    #[test]
    fn outcome_display() {
        assert_eq!(AttrOutcome::Pass.to_string(), "PASS");
        assert_eq!(AttrOutcome::Fail.to_string(), "FAIL");
        assert_eq!(AttrOutcome::Refusal.to_string(), "REFUSAL");
        assert_eq!(AttrOutcome::Blocked.to_string(), "BLOCKED");
    }

    #[test]
    fn outcome_is_pass_is_fail() {
        assert!(AttrOutcome::Pass.is_pass());
        assert!(!AttrOutcome::Pass.is_fail());
        assert!(AttrOutcome::Fail.is_fail());
        assert!(!AttrOutcome::Fail.is_pass());
        assert!(!AttrOutcome::Blocked.is_pass());
        assert!(!AttrOutcome::Blocked.is_fail());
        assert!(!AttrOutcome::Refusal.is_pass());
        assert!(!AttrOutcome::Refusal.is_fail());
    }

    // ── Report tests ───────────────────────────────────────────────────

    #[test]
    fn report_new_has_32_rows() {
        let report =
            AttrMetadataValidationReport::new("abc123", "2026-05-18T00:00:00Z", "test env");
        assert_eq!(report.rows.len(), 32);
        assert_eq!(report.commit, "abc123");
        assert_eq!(report.register_status, AttrMetadataRegisterStatus::Advanced);
    }

    #[test]
    fn report_count_by_outcome() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");
        report.rows[0] = report.rows[0].clone().pass();
        report.rows[1] = report.rows[1].clone().fail("err");
        report.rows[2] = report.rows[2].clone().refuse("no fuse");

        let (p, f, r, b) = report.count_by_outcome();
        assert_eq!(p, 1);
        assert_eq!(f, 1);
        assert_eq!(r, 1);
        assert_eq!(b, 29);
        assert_eq!(p + f + r + b, 32);
    }

    #[test]
    fn report_count_by_tier() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");
        // Canonical rows start with 8 ops at each of the 4 tiers
        let (clean, crash, readback, verify) = report.count_by_tier();
        assert_eq!(clean, 8);
        assert_eq!(crash, 8);
        assert_eq!(readback, 8);
        assert_eq!(verify, 8);

        // Override all rows to a single tier and verify recounting
        for row in &mut report.rows {
            row.tier = AttrValidationTier::PostCrashReadback;
        }
        let (clean, crash, readback, verify) = report.count_by_tier();
        assert_eq!(clean, 0);
        assert_eq!(crash, 0);
        assert_eq!(readback, 32);
        assert_eq!(verify, 0);
    }

    #[test]
    fn issue_1770_baseline_explains_every_blocked_row() {
        let report = AttrMetadataValidationReport::issue_1770_baseline(
            "abc123",
            "2026-07-02T00:00:00Z",
            "mounted FUSE runtime pending",
            "workflow_dispatch:qemu-smoke:fuse-inode-metadata-validation",
        );

        assert_eq!(
            report.artifact_scope.as_deref(),
            Some("workflow_dispatch:qemu-smoke:fuse-inode-metadata-validation")
        );
        let (pass, fail, refusal, blocked) = report.count_by_outcome();
        assert_eq!((pass, fail, refusal, blocked), (0, 0, 0, 32));
        for row in &report.rows {
            assert!(
                row.blocker.as_deref().is_some_and(|blocker| !blocker.is_empty()),
                "{} should carry an explicit blocker",
                row.name
            );
        }
    }

    #[test]
    fn issue_1770_baseline_does_not_claim_crash_or_root_verification() {
        let report = AttrMetadataValidationReport::issue_1770_baseline(
            "abc123",
            "2026-07-02T00:00:00Z",
            "mounted FUSE runtime pending",
            "pending artifact",
        );

        for row in report.rows.iter().filter(|row| {
            matches!(
                row.tier,
                AttrValidationTier::CrashDuringMutation
                    | AttrValidationTier::CommittedRootVerify
            )
        }) {
            assert_eq!(row.outcome, AttrOutcome::Blocked);
            let blocker = row.blocker.as_deref().unwrap_or_default();
            assert!(
                blocker.contains("fault-injection") || blocker.contains("committed-root"),
                "{} blocker should name the missing proof boundary: {blocker}",
                row.name
            );
        }
    }

    #[test]
    fn runtime_log_updates_only_canonical_rows() {
        let mut report = AttrMetadataValidationReport::issue_1770_baseline(
            "abc123",
            "2026-07-02T00:00:00Z",
            "mounted FUSE runtime",
            "pending artifact",
        );
        let summary = report.apply_runtime_log(
            "\
PASS: getattr-clean
  PASS: setattr-size-readback
FAIL: setattr-mode-readback -- mode changed after remount
REFUSAL: chown-clean -- root-capable mounted execution required
BLOCKED: chmod-crash -- no mid-mutation fault injector
PASS: metadata_test_exit_zero
",
            "actions/run/123/artifacts/fuse-inode-metadata-validation",
        );

        assert_eq!(summary.observed_rows, 5);
        assert_eq!(summary.ignored_lines, 1);
        assert_eq!(summary.pass, 2);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.refusal, 1);
        assert_eq!(summary.blocked, 1);

        let getattr = report
            .rows
            .iter()
            .find(|row| row.name == "getattr-clean")
            .unwrap();
        assert_eq!(getattr.outcome, AttrOutcome::Pass);
        assert!(getattr.blocker.is_none());
        assert_eq!(
            getattr.output_note.as_deref(),
            Some("actions/run/123/artifacts/fuse-inode-metadata-validation")
        );

        let mode = report
            .rows
            .iter()
            .find(|row| row.name == "setattr-mode-readback")
            .unwrap();
        assert_eq!(mode.outcome, AttrOutcome::Fail);
        assert_eq!(
            mode.blocker.as_deref(),
            Some("mode changed after remount")
        );

        let untouched = report
            .rows
            .iter()
            .find(|row| row.name == "utimens-verify")
            .unwrap();
        assert_eq!(untouched.outcome, AttrOutcome::Blocked);
        assert!(
            untouched
                .blocker
                .as_deref()
                .is_some_and(|blocker| blocker.contains("committed-root"))
        );
    }

    #[test]
    fn update_row_finds_by_name() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");
        let found = report.update_row(
            "chmod-crash",
            AttrOutcome::Pass,
            AttrValidationTier::CrashDuringMutation,
            None,
        );
        assert!(found);
        let row = report
            .rows
            .iter()
            .find(|r| r.name == "chmod-crash")
            .unwrap();
        assert_eq!(row.outcome, AttrOutcome::Pass);
        assert_eq!(row.tier, AttrValidationTier::CrashDuringMutation);
    }

    #[test]
    fn update_row_unknown_name_returns_false() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");
        assert!(!report.update_row(
            "nonexistent",
            AttrOutcome::Pass,
            AttrValidationTier::CleanRoundTrip,
            None,
        ));
    }

    #[test]
    fn apply_to_op_kind_updates_all_four() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");
        report.apply_to_op_kind(
            AttrOp::SetattrSize,
            AttrOutcome::Refusal,
            AttrValidationTier::CommittedRootVerify,
            Some("no fuse daemon".into()),
        );
        let size_rows: Vec<_> = report
            .rows
            .iter()
            .filter(|r| r.op_kind == AttrOp::SetattrSize)
            .collect();
        assert_eq!(size_rows.len(), 4);
        for row in size_rows {
            assert_eq!(row.outcome, AttrOutcome::Refusal);
            assert_eq!(row.tier, AttrValidationTier::CommittedRootVerify);
            assert_eq!(row.blocker.as_deref(), Some("no fuse daemon"));
        }
        // Other rows unchanged
        let other: Vec<_> = report
            .rows
            .iter()
            .filter(|r| r.op_kind != AttrOp::SetattrSize)
            .collect();
        assert_eq!(other.len(), 28);
        for row in other {
            assert_eq!(row.outcome, AttrOutcome::Blocked);
        }
    }

    #[test]
    fn advance_all_to_tier() {
        let mut report = AttrMetadataValidationReport::new("x", "y", "z");

        // Initial distribution: 8 rows at each of 4 tiers, all BLOCKED.
        assert_eq!(report.count_at_tier(AttrValidationTier::CleanRoundTrip), 8);
        assert_eq!(
            report.count_at_tier(AttrValidationTier::CrashDuringMutation),
            8
        );
        assert_eq!(
            report.count_at_tier(AttrValidationTier::PostCrashReadback),
            8
        );
        assert_eq!(
            report.count_at_tier(AttrValidationTier::CommittedRootVerify),
            8
        );

        // Step 1: advance CleanRoundTrip (tier 0) rows to CrashDuringMutation.
        // CrashDuringMutation/PostCrashReadback/CommittedRootVerify rows are
        // already at or above the target tier and remain unchanged.
        report.advance_all_to_tier(
            AttrValidationTier::CrashDuringMutation,
            AttrOutcome::Pass,
            None,
        );
        assert_eq!(
            report.count_at_tier(AttrValidationTier::CrashDuringMutation),
            16
        );
        // 8 rows advanced to PASS, 8 original Crash rows remain BLOCKED.
        let crash_pass = report
            .rows
            .iter()
            .filter(|r| {
                r.tier == AttrValidationTier::CrashDuringMutation && r.outcome == AttrOutcome::Pass
            })
            .count();
        let crash_blocked = report
            .rows
            .iter()
            .filter(|r| {
                r.tier == AttrValidationTier::CrashDuringMutation
                    && r.outcome == AttrOutcome::Blocked
            })
            .count();
        assert_eq!(crash_pass, 8);
        assert_eq!(crash_blocked, 8);

        // Step 2: advance all rows below CommittedRootVerify to that tier as REFUSAL.
        // The 8 original CommittedRootVerify rows remain BLOCKED (already at target).
        report.advance_all_to_tier(
            AttrValidationTier::CommittedRootVerify,
            AttrOutcome::Refusal,
            Some("no qemu available"),
        );
        assert_eq!(
            report.count_at_tier(AttrValidationTier::CommittedRootVerify),
            32
        );
        let verify_refusal = report
            .rows
            .iter()
            .filter(|r| {
                r.tier == AttrValidationTier::CommittedRootVerify
                    && r.outcome == AttrOutcome::Refusal
            })
            .count();
        let verify_blocked = report
            .rows
            .iter()
            .filter(|r| {
                r.tier == AttrValidationTier::CommittedRootVerify
                    && r.outcome == AttrOutcome::Blocked
            })
            .count();
        assert_eq!(verify_refusal, 24);
        assert_eq!(verify_blocked, 8);
    }

    #[test]
    fn markdown_renders_all_rows() {
        let report = AttrMetadataValidationReport::new(
            "abc123",
            "2026-05-18T00:00:00Z",
            "test VM with FUSE",
        );
        let md = report.to_markdown();
        assert!(md.contains("# TideFS FUSE Inode Metadata Validation Report"));
        assert!(md.contains("abc123"));
        assert!(md.contains("Advanced"));
        for row in &report.rows {
            assert!(
                md.contains(&row.description),
                "markdown missing: {}",
                row.description
            );
        }
    }

    #[test]
    fn markdown_contains_all_op_kind_labels() {
        let report = AttrMetadataValidationReport::new("x", "y", "z");
        let md = report.to_markdown();
        let expected = [
            "getattr",
            "setattr-size",
            "setattr-mode",
            "setattr-owner",
            "setattr-timestamps",
            "chmod",
            "chown",
            "utimens",
        ];
        for label in &expected {
            assert!(md.contains(label), "markdown missing label: {label}");
        }
    }

    #[test]
    fn register_status_variants_distinct() {
        let closed = AttrMetadataRegisterStatus::Closed;
        let advanced = AttrMetadataRegisterStatus::Advanced;
        let na = AttrMetadataRegisterStatus::NotApplicable;
        assert_ne!(closed, advanced);
        assert_ne!(advanced, na);
        assert_ne!(closed, na);
    }

    // ── Serde roundtrip tests ──────────────────────────────────────────

    #[test]
    fn serde_roundtrip_report() {
        let report = AttrMetadataValidationReport::new("abc123", "2026-05-18T00:00:00Z", "test");
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: AttrMetadataValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.commit, report.commit);
        assert_eq!(parsed.rows.len(), report.rows.len());
        assert_eq!(parsed.register_status, report.register_status);
        for (a, b) in report.rows.iter().zip(parsed.rows.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.op_kind, b.op_kind);
            assert_eq!(a.outcome, b.outcome);
            assert_eq!(a.tier, b.tier);
        }
    }

    #[test]
    fn serde_op_kind_roundtrip() {
        let kinds = vec![
            AttrOp::Getattr,
            AttrOp::SetattrSize,
            AttrOp::SetattrMode,
            AttrOp::SetattrOwner,
            AttrOp::SetattrTimestamps,
            AttrOp::Chmod,
            AttrOp::Chown,
            AttrOp::Utimens,
        ];
        let json = serde_json::to_string(&kinds).unwrap();
        let parsed: Vec<AttrOp> = serde_json::from_str(&json).unwrap();
        assert_eq!(kinds, parsed);
    }

    #[test]
    fn serde_tier_roundtrip() {
        let tiers = vec![
            AttrValidationTier::CleanRoundTrip,
            AttrValidationTier::CrashDuringMutation,
            AttrValidationTier::PostCrashReadback,
            AttrValidationTier::CommittedRootVerify,
        ];
        let json = serde_json::to_string(&tiers).unwrap();
        let parsed: Vec<AttrValidationTier> = serde_json::from_str(&json).unwrap();
        assert_eq!(tiers, parsed);
    }

    // ── Edge case tests ────────────────────────────────────────────────

    #[test]
    fn mode_only_setattr_presence() {
        let rows = canonical_fuse_inode_metadata_rows();
        let mode_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.op_kind == AttrOp::SetattrMode)
            .collect();
        assert_eq!(mode_rows.len(), 4);
        let mut tier_set = std::collections::HashSet::new();
        for row in &mode_rows {
            tier_set.insert(row.tier);
        }
        assert_eq!(tier_set.len(), 4);
    }

    #[test]
    fn dual_setattr_coverage() {
        let rows = canonical_fuse_inode_metadata_rows();
        let size_crash = rows.iter().find(|r| {
            r.op_kind == AttrOp::SetattrSize && r.tier == AttrValidationTier::CrashDuringMutation
        });
        let owner_crash = rows.iter().find(|r| {
            r.op_kind == AttrOp::SetattrOwner && r.tier == AttrValidationTier::CrashDuringMutation
        });
        assert!(size_crash.is_some(), "setattr-size crash row missing");
        assert!(owner_crash.is_some(), "setattr-owner crash row missing");
    }

    #[test]
    fn utimens_coverage() {
        let rows = canonical_fuse_inode_metadata_rows();
        let utimens_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.op_kind == AttrOp::Utimens)
            .collect();
        assert_eq!(utimens_rows.len(), 4);
        for tier in &[
            AttrValidationTier::CleanRoundTrip,
            AttrValidationTier::CrashDuringMutation,
            AttrValidationTier::PostCrashReadback,
            AttrValidationTier::CommittedRootVerify,
        ] {
            assert!(
                utimens_rows.iter().any(|r| r.tier == *tier),
                "utimens missing tier {tier:?}"
            );
        }
    }

    #[test]
    fn report_new_env_disclosure() {
        let report = AttrMetadataValidationReport::new(
            "abc123",
            "2026-05-18T12:00:00+02:00",
            "Linux 7.0 QEMU, FUSE daemon running, tidefs-fuser loaded",
        );
        assert!(report.environment.contains("QEMU"));
        assert!(report.environment.contains("FUSE"));
        assert!(report.environment.contains("tidefs-fuser"));
    }

    #[test]
    fn crash_consistency_rows_present() {
        let rows = canonical_fuse_inode_metadata_rows();
        let crash_rows: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.tier == AttrValidationTier::CrashDuringMutation
                    || r.tier == AttrValidationTier::PostCrashReadback
                    || r.tier == AttrValidationTier::CommittedRootVerify
            })
            .collect();
        assert_eq!(
            crash_rows.len(),
            24,
            "expected 24 crash-tier rows (3 tiers x 8 ops)"
        );
    }
}
