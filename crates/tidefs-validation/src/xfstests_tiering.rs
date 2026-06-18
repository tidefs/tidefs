// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! xfstests tiering policy — maps xfstests groups to validation tiers,
//! defines explicit expected-failure catalogs, and validates scoreboard
//! runs against the tiering policy.
//!
//! The core invariant: every xfstests test exercised in a scored run must
//! be explicitly classified. Pass is release validation; ExpectedFail is an
//! acknowledged gap with a concrete reason; Skip is explicitly out-of-scope.
//! There is no hidden PASS — a test that is exercised but not classified is
//! a policy violation.
//!
//! # Tier mapping
//!
//! | xfstests group | Validation tier | Runtime |
//! |---------------|--------------|---------|
//! | quick         | Tier 3       | Mounted userspace (FUSE) |
//! | auto          | Tier 3       | Mounted userspace (FUSE) |
//! | lock          | Tier 3       | Mounted userspace (FUSE) |
//! | all           | Tier 5       | Mounted kernel VFS |

#![deny(dead_code)]
#![deny(unused_imports)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::xfstests_scoreboard::{XfstestsClassification, XfstestsScoreboard};

// -- Validation tier --------------------------------------------------------

/// Validation tiers as defined in `docs/CURRENT_RELEASE_FOCUS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationTier {
    /// Source/model/schema/proposal state.
    Tier0,
    /// Cargo/unit/focused crate tests.
    Tier1,
    /// Harness without a mounted/live product path.
    Tier2,
    /// Mounted userspace or QEMU guest runtime.
    Tier3,
    /// Linux 7.0 Kbuild and QEMU module load.
    Tier4,
    /// Mounted kernel VFS or kernel block I/O.
    Tier5,
    /// Full-kernel no-daemon mounted operation.
    Tier6,
    /// Multi-process distributed/RDMA runtime.
    Tier7,
}

impl ValidationTier {
    /// Short label suitable for display and serialization.
    pub fn label(&self) -> &'static str {
        match self {
            ValidationTier::Tier0 => "Tier 0",
            ValidationTier::Tier1 => "Tier 1",
            ValidationTier::Tier2 => "Tier 2",
            ValidationTier::Tier3 => "Tier 3",
            ValidationTier::Tier4 => "Tier 4",
            ValidationTier::Tier5 => "Tier 5",
            ValidationTier::Tier6 => "Tier 6",
            ValidationTier::Tier7 => "Tier 7",
        }
    }

    /// Whether this tier requires live runtime validation.
    pub fn requires_runtime(&self) -> bool {
        matches!(
            self,
            ValidationTier::Tier3
                | ValidationTier::Tier4
                | ValidationTier::Tier5
                | ValidationTier::Tier6
                | ValidationTier::Tier7
        )
    }

    /// Whether cargo/source/schema validation alone can close this tier.
    pub fn allows_cargo_closure(&self) -> bool {
        matches!(
            self,
            ValidationTier::Tier0 | ValidationTier::Tier1 | ValidationTier::Tier2
        )
    }
}

// -- Group tier definition -------------------------------------------------

/// Maps an xfstests group name to an validation tier and runtime context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupTier {
    /// xfstests group name (e.g. "quick", "auto", "lock").
    pub group: String,
    /// Validation tier required for this group.
    pub tier: ValidationTier,
    /// Runtime context (e.g. "FUSE userspace", "kernel VFS").
    pub runtime: String,
    /// Human-readable description of what this group covers.
    #[serde(default)]
    pub description: String,
}

// -- Expected-failure catalog -----------------------------------------------

/// A single entry in the expected-failure catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedFailureEntry {
    /// Full test name, e.g. "generic/099".
    pub test: String,
    /// Feature area tag (e.g. "ACL", "MMAP", "ENCRYPT").
    pub feature_area: String,
    /// Why this test is expected to fail.
    pub reason: String,
    /// The xfstests group(s) where this expected failure applies.
    #[serde(default)]
    pub groups: Vec<String>,
    /// The validation tier at which this failure is expected to become a pass.
    #[serde(default)]
    pub target_tier: Option<ValidationTier>,
}

/// Catalog of tests expected to fail, organized by feature area.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExpectedFailureCatalog {
    /// Version for format evolution.
    #[serde(default = "default_catalog_version")]
    pub version: u32,
    /// Entries organized as a flat list.
    pub entries: Vec<ExpectedFailureEntry>,
}

fn default_catalog_version() -> u32 {
    1
}

impl ExpectedFailureCatalog {
    /// Lookup the expected-failure reason for a test, if any.
    pub fn find(&self, test: &str) -> Option<&ExpectedFailureEntry> {
        self.entries.iter().find(|e| e.test == test)
    }

    /// Whether a test is expected to fail.
    pub fn is_expected_failure(&self, test: &str) -> bool {
        self.find(test).is_some()
    }

    /// Feature areas represented in the catalog.
    pub fn feature_areas(&self) -> Vec<&str> {
        let mut areas: Vec<&str> = self
            .entries
            .iter()
            .map(|e| e.feature_area.as_str())
            .collect();
        areas.sort();
        areas.dedup();
        areas
    }
}

// -- Tiering policy ---------------------------------------------------------

/// Complete xfstests tiering policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XfstestsTieringPolicy {
    /// Policy version for format evolution.
    #[serde(default = "default_policy_version")]
    pub version: u32,
    /// Group-to-tier mappings.
    pub groups: Vec<GroupTier>,
    /// Expected-failure catalog.
    pub expected_failures: ExpectedFailureCatalog,
}

fn default_policy_version() -> u32 {
    1
}

impl XfstestsTieringPolicy {
    /// Resolve the validation tier for an xfstests group name.
    pub fn tier_for_group(&self, group: &str) -> Option<ValidationTier> {
        self.groups
            .iter()
            .find(|g| g.group == group)
            .map(|g| g.tier)
    }

    /// Lookup a test in the expected-failure catalog.
    pub fn expected_failure_for(&self, test: &str) -> Option<&ExpectedFailureEntry> {
        self.expected_failures.find(test)
    }

    /// Default tiering policy for current-head TideFS.
    pub fn default_policy() -> Self {
        XfstestsTieringPolicy {
            version: 1,
            groups: vec![
                GroupTier {
                    group: "quick".to_string(),
                    tier: ValidationTier::Tier3,
                    runtime: "FUSE userspace".to_string(),
                    description: "Quick smoke group — core POSIX operations on FUSE mount."
                        .to_string(),
                },
                GroupTier {
                    group: "auto".to_string(),
                    tier: ValidationTier::Tier3,
                    runtime: "FUSE userspace".to_string(),
                    description: "Auto group — broader POSIX coverage on FUSE mount.".to_string(),
                },
                GroupTier {
                    group: "lock".to_string(),
                    tier: ValidationTier::Tier3,
                    runtime: "FUSE userspace".to_string(),
                    description: "POSIX file locking correctness on FUSE mount.".to_string(),
                },
                GroupTier {
                    group: "all".to_string(),
                    tier: ValidationTier::Tier5,
                    runtime: "kernel VFS".to_string(),
                    description: "Full test suite on mounted kernel VFS.".to_string(),
                },
            ],
            expected_failures: ExpectedFailureCatalog {
                version: 1,
                entries: vec![
                    ExpectedFailureEntry {
                        test: "generic/099".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["quick".to_string(), "auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                    ExpectedFailureEntry {
                        test: "generic/237".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                    ExpectedFailureEntry {
                        test: "generic/307".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                    ExpectedFailureEntry {
                        test: "generic/318".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                    ExpectedFailureEntry {
                        test: "generic/319".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                    ExpectedFailureEntry {
                        test: "generic/444".to_string(),
                        feature_area: "ACL".to_string(),
                        reason: "ACL set/get/inherit/default suite not yet passing end-to-end"
                            .to_string(),
                        groups: vec!["auto".to_string()],
                        target_tier: Some(ValidationTier::Tier3),
                    },
                ],
            },
        }
    }
}

// -- Policy validation ------------------------------------------------------

/// Result of validating a scoreboard against the tiering policy.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyValidationReport {
    /// The group name the scoreboard was run against (if known).
    pub group: String,
    /// Validation tier for this group.
    pub tier: ValidationTier,
    /// Total tests in the scoreboard.
    pub total: usize,
    /// Tests that passed (positive validation).
    pub passed: usize,
    /// Tests that failed unexpectedly (product defect, not in catalog).
    pub unexpected_failures: Vec<String>,
    /// Tests that passed unexpectedly (were in the expected-failure catalog
    /// but passed — improvement that should trigger catalog update).
    pub unexpected_passes: Vec<String>,
    /// Tests that are expected failures per the catalog and did fail.
    pub expected_failures: Vec<String>,
    /// Tests in the catalog that were not exercised (still expected failures,
    /// but not measured in this run).
    pub unexercised_expected_failures: Vec<String>,
    /// Tests that were skipped with no catalog entry (hidden skip).
    pub unclassified_skips: Vec<String>,
    /// Tests with environment refusals.
    pub env_refusals: Vec<String>,
}

impl PolicyValidationReport {
    /// Whether the run is policy-conformant.
    pub fn is_conformant(&self) -> bool {
        self.unexpected_failures.is_empty() && self.unclassified_skips.is_empty()
    }

    /// Whether the run reveals product defects (unexpected failures).
    pub fn has_defects(&self) -> bool {
        !self.unexpected_failures.is_empty()
    }

    /// Whether improvements were detected (catalog entries that passed).
    pub fn has_improvements(&self) -> bool {
        !self.unexpected_passes.is_empty()
    }
}

/// Validate a scoreboard against the tiering policy.
pub fn validate_against_policy(
    scoreboard: &XfstestsScoreboard,
    policy: &XfstestsTieringPolicy,
    group: &str,
) -> PolicyValidationReport {
    let tier = policy
        .tier_for_group(group)
        .unwrap_or(ValidationTier::Tier0);

    let mut report = PolicyValidationReport {
        group: group.to_string(),
        tier,
        total: scoreboard.results.len(),
        passed: 0,
        unexpected_failures: Vec::new(),
        unexpected_passes: Vec::new(),
        expected_failures: Vec::new(),
        unexercised_expected_failures: Vec::new(),
        unclassified_skips: Vec::new(),
        env_refusals: Vec::new(),
    };

    let mut exercised_catalog_tests: BTreeSet<&str> = BTreeSet::new();

    for entry in &scoreboard.results {
        let classification = entry.status.classify();
        let in_catalog = policy
            .expected_failures
            .find(&entry.test)
            .map(|e| e.groups.is_empty() || e.groups.iter().any(|g| g == group))
            .unwrap_or(false);

        match classification {
            XfstestsClassification::Pass => {
                report.passed += 1;
                if in_catalog {
                    report.unexpected_passes.push(entry.test.clone());
                    exercised_catalog_tests.insert(&entry.test);
                }
            }
            XfstestsClassification::Fail => {
                if in_catalog {
                    report.expected_failures.push(entry.test.clone());
                    exercised_catalog_tests.insert(&entry.test);
                } else {
                    report.unexpected_failures.push(entry.test.clone());
                }
            }
            XfstestsClassification::ExpectedFail => {
                report.expected_failures.push(entry.test.clone());
                if policy.expected_failures.find(&entry.test).is_some() {
                    exercised_catalog_tests.insert(&entry.test);
                }
            }
            XfstestsClassification::Skip => {
                if !in_catalog {
                    report.unclassified_skips.push(entry.test.clone());
                }
            }
            XfstestsClassification::EnvironmentRefusal => {
                report.env_refusals.push(entry.test.clone());
            }
        }
    }

    // Catalog entries that weren't exercised at all.
    let catalog_tests_for_group: Vec<String> = policy
        .expected_failures
        .entries
        .iter()
        .filter(|e| e.groups.is_empty() || e.groups.iter().any(|g| g == group))
        .map(|e| e.test.clone())
        .collect();

    for test in &catalog_tests_for_group {
        if !exercised_catalog_tests.contains(test.as_str())
            && !report.unexpected_passes.contains(test)
        {
            report.unexercised_expected_failures.push(test.clone());
        }
    }

    report
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfstests_scoreboard::{ScoreboardEntry, ScoreboardSummary, TestStatus};

    fn make_scoreboard(results: Vec<(&str, TestStatus)>) -> XfstestsScoreboard {
        let entries: Vec<ScoreboardEntry> = results
            .into_iter()
            .map(|(test, status)| ScoreboardEntry {
                test: test.to_string(),
                status,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: None,
            })
            .collect();
        let total = entries.len();
        let passed = entries
            .iter()
            .filter(|e| e.status == TestStatus::Pass)
            .count();
        let failed = entries
            .iter()
            .filter(|e| e.status == TestStatus::Fail || e.status == TestStatus::Diff)
            .count();
        let skipped = entries
            .iter()
            .filter(|e| e.status == TestStatus::Skip)
            .count();
        let expected_fail = entries
            .iter()
            .filter(|e| e.status == TestStatus::ExpectedFail)
            .count();
        let env_refusal = entries
            .iter()
            .filter(|e| e.status == TestStatus::EnvironmentRefusal)
            .count();

        XfstestsScoreboard {
            started_at: "test".to_string(),
            duration_secs: 1.0,
            command: "check".to_string(),
            test_range: "test".to_string(),
            results: entries,
            summary: ScoreboardSummary {
                total,
                passed,
                failed,
                skipped,
                diff: 0,
                expected_fail,
                env_refusal,
            },
        }
    }

    fn default_policy() -> XfstestsTieringPolicy {
        XfstestsTieringPolicy::default_policy()
    }

    #[test]
    fn tier_for_group_quick() {
        let policy = default_policy();
        assert_eq!(policy.tier_for_group("quick"), Some(ValidationTier::Tier3));
    }

    #[test]
    fn tier_for_group_auto() {
        let policy = default_policy();
        assert_eq!(policy.tier_for_group("auto"), Some(ValidationTier::Tier3));
    }

    #[test]
    fn tier_for_group_all() {
        let policy = default_policy();
        assert_eq!(policy.tier_for_group("all"), Some(ValidationTier::Tier5));
    }

    #[test]
    fn tier_for_unknown_group_returns_none() {
        let policy = default_policy();
        assert_eq!(policy.tier_for_group("nonexistent"), None);
    }

    #[test]
    fn catalog_find_existing_test() {
        let policy = default_policy();
        let found = policy.expected_failure_for("generic/099");
        assert!(found.is_some());
        assert_eq!(found.unwrap().feature_area, "ACL");
    }

    #[test]
    fn catalog_find_nonexistent_test() {
        let policy = default_policy();
        assert!(policy.expected_failure_for("generic/999").is_none());
    }

    #[test]
    fn tier3_requires_runtime() {
        assert!(ValidationTier::Tier3.requires_runtime());
    }

    #[test]
    fn tier1_allows_cargo_closure() {
        assert!(ValidationTier::Tier1.allows_cargo_closure());
    }

    #[test]
    fn tier5_requires_runtime() {
        assert!(ValidationTier::Tier5.requires_runtime());
    }

    #[test]
    fn tier5_does_not_allow_cargo_closure() {
        assert!(!ValidationTier::Tier5.allows_cargo_closure());
    }

    #[test]
    fn all_pass_is_conformant() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![
            ("generic/001", TestStatus::Pass),
            ("generic/002", TestStatus::Pass),
        ]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report.is_conformant());
        assert!(!report.has_defects());
        assert_eq!(report.passed, 2);
        assert!(report.unexpected_failures.is_empty());
        assert!(report.unclassified_skips.is_empty());
    }

    #[test]
    fn unexpected_failure_is_defect() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![
            ("generic/001", TestStatus::Pass),
            ("generic/050", TestStatus::Fail),
        ]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(!report.is_conformant());
        assert!(report.has_defects());
        assert_eq!(report.unexpected_failures, vec!["generic/050"]);
    }

    #[test]
    fn catalog_entry_failing_is_conformant() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![
            ("generic/099", TestStatus::Fail),
            ("generic/001", TestStatus::Pass),
        ]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report.is_conformant());
        assert_eq!(report.expected_failures, vec!["generic/099"]);
    }

    #[test]
    fn catalog_entry_passing_is_improvement() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![("generic/099", TestStatus::Pass)]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report.is_conformant());
        assert!(report.has_improvements());
        assert_eq!(report.unexpected_passes, vec!["generic/099"]);
    }

    #[test]
    fn unclassified_skip_is_policy_gap() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![("generic/900", TestStatus::Skip)]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(!report.is_conformant());
        assert_eq!(report.unclassified_skips, vec!["generic/900"]);
    }

    #[test]
    fn env_refusal_not_a_violation() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![("generic/001", TestStatus::EnvironmentRefusal)]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report.is_conformant());
        assert_eq!(report.env_refusals, vec!["generic/001"]);
    }

    #[test]
    fn harness_expected_fail_always_conformant() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![("generic/050", TestStatus::ExpectedFail)]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report.is_conformant());
        assert_eq!(report.expected_failures, vec!["generic/050"]);
    }

    #[test]
    fn unexercised_catalog_entries_tracked() {
        let policy = default_policy();
        let sb = make_scoreboard(vec![("generic/001", TestStatus::Pass)]);
        let report = validate_against_policy(&sb, &policy, "quick");
        assert!(report
            .unexercised_expected_failures
            .contains(&"generic/099".to_string()));
    }

    #[test]
    fn policy_json_roundtrip() {
        let policy = default_policy();
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let parsed: XfstestsTieringPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.groups.len(), policy.groups.len());
        assert_eq!(
            parsed.expected_failures.entries.len(),
            policy.expected_failures.entries.len()
        );
    }

    #[test]
    fn catalog_feature_areas() {
        let policy = default_policy();
        let areas = policy.expected_failures.feature_areas();
        assert_eq!(areas, vec!["ACL"]);
    }

    #[test]
    fn validation_report_serialization() {
        let report = PolicyValidationReport {
            group: "quick".to_string(),
            tier: ValidationTier::Tier3,
            total: 2,
            passed: 1,
            unexpected_failures: vec!["generic/050".to_string()],
            unexpected_passes: vec![],
            expected_failures: vec!["generic/099".to_string()],
            unexercised_expected_failures: vec![],
            unclassified_skips: vec![],
            env_refusals: vec![],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("generic/050"));
        assert!(json.contains("generic/099"));
        assert!(json.contains("tier3"));
    }
}
