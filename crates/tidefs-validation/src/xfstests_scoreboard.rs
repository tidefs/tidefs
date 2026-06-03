//! xfstests scoreboard integration -- invokes the TideFS xfstests harness,
//! captures structured JSON results, and supports regression detection.
//!
//! When xfstests or the daemon binary is unavailable, the harness reports
//! skip rather than panicking, so `cargo test` always succeeds.
//!
//! # Classification taxonomy
//!
//! Every xfstests row is classified into exactly one of five categories:
//!
//! | Classification      | Meaning |
//! |---------------------|---------|
//! | `Pass`              | The test passed on TideFS; product behavior matches expected kernel behavior. |
//! | `Fail`              | The test exercised a real product defect (wrong output, crash, hang, data corruption). |
//! | `ExpectedFail`      | The test exercised a known limitation, intentional cut, or acknowledged gap that has not yet been addressed. |
//! | `Skip`              | The test was intentionally not exercised for this run (out of scope, not yet wired). |
//! | `EnvironmentRefusal`| The environment could not satisfy the test workload (missing /dev/fuse, /dev/kvm, kernel module, insufficient privilege). |
//!
//! Only `Pass` counts as passing release validation. Skips, environment
//! refusals, and expected failures are explicitly non-pass outcomes and
//! must not be conflated with passing results. A test that moves from
//! Skip to Fail is not a regression (Skip was never validation of correct
//! behavior). A test that moves from ExpectedFail to Pass is an improvement.

#![deny(dead_code)]
#![deny(unused_imports)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::process::Command;

// -- Scoreboard types (lightweight; mirrors daemon types for decoding) --

/// Per-test status as produced by the xfstests harness.
///
/// This is the on-wire representation. Use `TestStatus::classify()` to
/// map into the normalized `XfstestsClassification` for validation aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    /// Test passed.
    Pass,
    /// Test failed (product defect).
    Fail,
    /// Test was intentionally not run.
    Skip,
    /// Output differed from expected golden output.
    Diff,
    /// Test failed but the failure was expected (known limitation, intentional cut).
    #[serde(rename = "expected-fail")]
    ExpectedFail,
    /// Environment could not satisfy the test workload.
    #[serde(rename = "environment-refusal")]
    EnvironmentRefusal,
}

/// Normalized xfstests classification for validation aggregation and release gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XfstestsClassification {
    Pass,
    Fail,
    ExpectedFail,
    Skip,
    EnvironmentRefusal,
}

impl TestStatus {
    /// Map the on-wire test status to the normalized classification.
    pub fn classify(&self) -> XfstestsClassification {
        match self {
            TestStatus::Pass => XfstestsClassification::Pass,
            TestStatus::Fail => XfstestsClassification::Fail,
            TestStatus::Diff => XfstestsClassification::Fail,
            TestStatus::ExpectedFail => XfstestsClassification::ExpectedFail,
            TestStatus::Skip => XfstestsClassification::Skip,
            TestStatus::EnvironmentRefusal => XfstestsClassification::EnvironmentRefusal,
        }
    }

    /// Whether this status represents passing release validation.
    ///
    /// Only `Pass` counts. Skips, environment refusals, and expected
    /// failures are explicitly non-pass outcomes.
    pub fn is_pass_validation(&self) -> bool {
        matches!(self, TestStatus::Pass)
    }
}

impl XfstestsClassification {
    /// Short label for display and summary tables.
    pub fn label(&self) -> &'static str {
        match self {
            XfstestsClassification::Pass => "PASS",
            XfstestsClassification::Fail => "FAIL",
            XfstestsClassification::ExpectedFail => "EXPECTED_FAIL",
            XfstestsClassification::Skip => "SKIP",
            XfstestsClassification::EnvironmentRefusal => "ENV_REFUSAL",
        }
    }

    /// Whether this classification counts as passing release validation.
    pub fn is_pass_validation(&self) -> bool {
        matches!(self, XfstestsClassification::Pass)
    }

    /// Whether this classification represents a product defect.
    pub fn is_product_fail(&self) -> bool {
        matches!(self, XfstestsClassification::Fail)
    }

    /// Whether this classification is non-validation (skip or environment refusal).
    pub fn is_non_validation(&self) -> bool {
        matches!(
            self,
            XfstestsClassification::Skip | XfstestsClassification::EnvironmentRefusal
        )
    }
}

impl fmt::Display for XfstestsClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardEntry {
    pub test: String,
    pub status: TestStatus,
    #[serde(default)]
    pub duration_secs: Option<f64>,
    #[serde(default)]
    pub output_diff: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Per-test classification entry for validation aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationEntry {
    pub test: String,
    pub status: TestStatus,
    pub classification: XfstestsClassification,
    #[serde(default)]
    pub duration_secs: Option<f64>,
    #[serde(default)]
    pub output_diff: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl From<ScoreboardEntry> for ClassificationEntry {
    fn from(entry: ScoreboardEntry) -> Self {
        let classification = entry.status.classify();
        ClassificationEntry {
            test: entry.test,
            status: entry.status,
            classification,
            duration_secs: entry.duration_secs,
            output_diff: entry.output_diff,
            reason: entry.reason,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub diff: usize,
    /// Tests that failed but were expected to fail.
    #[serde(default)]
    pub expected_fail: usize,
    /// Tests that could not run due to environment limitations.
    #[serde(default)]
    pub env_refusal: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XfstestsScoreboard {
    pub started_at: String,
    pub duration_secs: f64,
    pub command: String,
    pub test_range: String,
    pub results: Vec<ScoreboardEntry>,
    pub summary: ScoreboardSummary,
}

impl XfstestsScoreboard {
    /// Produce a classification summary from the raw scoreboard.
    pub fn classify(&self) -> ClassificationSummary {
        let mut counts = ClassificationCounts::default();
        let mut entries: Vec<ClassificationEntry> = Vec::with_capacity(self.results.len());

        for entry in &self.results {
            let ce = ClassificationEntry::from(entry.clone());
            match ce.classification {
                XfstestsClassification::Pass => counts.pass += 1,
                XfstestsClassification::Fail => counts.fail += 1,
                XfstestsClassification::ExpectedFail => counts.expected_fail += 1,
                XfstestsClassification::Skip => counts.skip += 1,
                XfstestsClassification::EnvironmentRefusal => counts.env_refusal += 1,
            }
            entries.push(ce);
        }

        ClassificationSummary {
            test_range: self.test_range.clone(),
            counts,
            entries,
        }
    }
}

/// Aggregate classification counts for a scoreboard run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassificationCounts {
    pub pass: usize,
    pub fail: usize,
    pub expected_fail: usize,
    pub skip: usize,
    pub env_refusal: usize,
}

impl ClassificationCounts {
    pub fn total(&self) -> usize {
        self.pass + self.fail + self.expected_fail + self.skip + self.env_refusal
    }

    /// Number of tests that provide positive release validation.
    pub fn passes(&self) -> usize {
        self.pass
    }

    /// Number of tests that indicate product defects.
    pub fn product_failures(&self) -> usize {
        self.fail
    }

    /// Number of tests that are non-validation (skip + env refusal).
    pub fn non_validation(&self) -> usize {
        self.skip + self.env_refusal
    }
}

/// Classification summary produced from a raw scoreboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationSummary {
    pub test_range: String,
    pub counts: ClassificationCounts,
    pub entries: Vec<ClassificationEntry>,
}

impl ClassificationSummary {
    /// Tests that passed.
    pub fn passing_tests(&self) -> Vec<&ClassificationEntry> {
        self.entries
            .iter()
            .filter(|e| e.classification.is_pass_validation())
            .collect()
    }

    /// Tests with product defects.
    pub fn failing_tests(&self) -> Vec<&ClassificationEntry> {
        self.entries
            .iter()
            .filter(|e| e.classification.is_product_fail())
            .collect()
    }

    /// Tests that are expected failures (known limitations).
    pub fn expected_failures(&self) -> Vec<&ClassificationEntry> {
        self.entries
            .iter()
            .filter(|e| e.classification == XfstestsClassification::ExpectedFail)
            .collect()
    }

    /// Tests that are non-validation (skip or environment refusal).
    pub fn non_validation_entries(&self) -> Vec<&ClassificationEntry> {
        self.entries
            .iter()
            .filter(|e| e.classification.is_non_validation())
            .collect()
    }
}

// -- Regression detection -------------------------------------------------

/// Result of comparing two scoreboards using normalized classifications.
///
/// Regression detection uses `XfstestsClassification` so that:
/// - Skip and EnvironmentRefusal are never treated as passing validation
/// - ExpectedFail -> Pass is an improvement, not a regression
/// - Pass -> Fail is a regression
/// - ExpectedFail -> ExpectedFail is neutral (known gap persists)
/// - Skip -> Fail is NOT a regression (Skip was never validation)
#[derive(Debug, Clone, Serialize)]
pub struct RegressionReport {
    /// Baseline test range.
    pub baseline_range: String,
    /// Current test range.
    pub current_range: String,
    /// Tests that were passing but now fail/diff.
    pub regressions: Vec<String>,
    /// Tests that were failing but now pass.
    pub improvements: Vec<String>,
    /// Tests that appear only in current (new coverage).
    pub new_tests: Vec<String>,
    /// Tests that appear only in baseline (removed coverage).
    pub removed_tests: Vec<String>,
    /// Summary comparison.
    pub baseline_summary: ScoreboardSummary,
    pub current_summary: ScoreboardSummary,
    /// Baseline classification counts.
    #[serde(default)]
    pub baseline_classification: Option<ClassificationCounts>,
    /// Current classification counts.
    #[serde(default)]
    pub current_classification: Option<ClassificationCounts>,
}

/// Whether a classification counts as "passing" for regression baselines.
///
/// Only `XfstestsClassification::Pass` is treated as passing validation.
/// Skip, EnvironmentRefusal, and ExpectedFail are not passing.
fn is_passing_for_regression(c: XfstestsClassification) -> bool {
    c.is_pass_validation()
}

/// Whether a classification counts as "failing" for regression detection.
fn is_failing_for_regression(c: XfstestsClassification) -> bool {
    matches!(c, XfstestsClassification::Fail)
}

impl RegressionReport {
    /// Whether any regressions were detected.
    ///
    /// Only genuine regressions (Pass -> Fail) are counted. Skip -> Fail,
    /// ExpectedFail -> Fail, and EnvironmentRefusal -> Fail are not regressions
    /// because the baseline was not passing validation.
    pub fn has_regressions(&self) -> bool {
        !self.regressions.is_empty()
    }

    /// Whether the current run shows strictly non-worse results.
    ///
    /// Clean means no regressions and no removed tests.
    pub fn is_clean(&self) -> bool {
        self.regressions.is_empty() && self.removed_tests.is_empty()
    }
}

/// Compare two scoreboards using normalized classifications.
///
/// A regression is defined as a test that was `XfstestsClassification::Pass`
/// in the baseline but is `XfstestsClassification::Fail` in the current run.
/// Skip, EnvironmentRefusal, and ExpectedFail in the baseline are never treated
/// as passing validation, so their transition to Fail does not create a regression.
///
/// Improvements are defined as a test that was failing (Fail or ExpectedFail)
/// in the baseline but is Pass in the current run.
pub fn compare_scoreboards(
    baseline: &XfstestsScoreboard,
    current: &XfstestsScoreboard,
) -> RegressionReport {
    use std::collections::{BTreeMap, BTreeSet};

    let mut baseline_map: BTreeMap<&str, XfstestsClassification> = BTreeMap::new();
    for entry in &baseline.results {
        baseline_map.insert(entry.test.as_str(), entry.status.classify());
    }

    let mut current_map: BTreeMap<&str, XfstestsClassification> = BTreeMap::new();
    for entry in &current.results {
        current_map.insert(entry.test.as_str(), entry.status.classify());
    }

    let baseline_tests: BTreeSet<&str> = baseline_map.keys().copied().collect();
    let current_tests: BTreeSet<&str> = current_map.keys().copied().collect();

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();

    for test in baseline_tests.intersection(&current_tests) {
        let base = baseline_map[test];
        let curr = current_map[test];

        // Regression: was passing, now failing.
        if is_passing_for_regression(base) && is_failing_for_regression(curr) {
            regressions.push(test.to_string());
        }
        // Improvement: was failing or expected-fail, now passing.
        if (is_failing_for_regression(base) || base == XfstestsClassification::ExpectedFail)
            && curr.is_pass_validation()
        {
            improvements.push(test.to_string());
        }
        // ExpectedFail -> ExpectedFail = neutral (no regression, no improvement).
        // Skip -> Fail = NOT a regression (Skip was never validation).
        // EnvironmentRefusal -> anything = NOT a regression.
    }

    let new_tests: Vec<String> = current_tests
        .difference(&baseline_tests)
        .map(|s| s.to_string())
        .collect();

    let removed_tests: Vec<String> = baseline_tests
        .difference(&current_tests)
        .map(|s| s.to_string())
        .collect();

    let baseline_classification = ClassificationCounts {
        pass: baseline
            .results
            .iter()
            .filter(|e| e.status.classify().is_pass_validation())
            .count(),
        fail: baseline
            .results
            .iter()
            .filter(|e| e.status.classify().is_product_fail())
            .count(),
        expected_fail: baseline
            .results
            .iter()
            .filter(|e| matches!(e.status.classify(), XfstestsClassification::ExpectedFail))
            .count(),
        skip: baseline
            .results
            .iter()
            .filter(|e| matches!(e.status.classify(), XfstestsClassification::Skip))
            .count(),
        env_refusal: baseline
            .results
            .iter()
            .filter(|e| {
                matches!(
                    e.status.classify(),
                    XfstestsClassification::EnvironmentRefusal
                )
            })
            .count(),
    };
    let current_classification = ClassificationCounts {
        pass: current
            .results
            .iter()
            .filter(|e| e.status.classify().is_pass_validation())
            .count(),
        fail: current
            .results
            .iter()
            .filter(|e| e.status.classify().is_product_fail())
            .count(),
        expected_fail: current
            .results
            .iter()
            .filter(|e| matches!(e.status.classify(), XfstestsClassification::ExpectedFail))
            .count(),
        skip: current
            .results
            .iter()
            .filter(|e| matches!(e.status.classify(), XfstestsClassification::Skip))
            .count(),
        env_refusal: current
            .results
            .iter()
            .filter(|e| {
                matches!(
                    e.status.classify(),
                    XfstestsClassification::EnvironmentRefusal
                )
            })
            .count(),
    };

    RegressionReport {
        baseline_range: baseline.test_range.clone(),
        current_range: current.test_range.clone(),
        regressions,
        improvements,
        new_tests,
        removed_tests,
        baseline_summary: baseline.summary.clone(),
        current_summary: current.summary.clone(),
        baseline_classification: Some(baseline_classification),
        current_classification: Some(current_classification),
    }
}

// -- Harness invocation ---------------------------------------------------

/// Load a scoreboard from a JSON file.
pub fn load_scoreboard(path: &Path) -> Result<XfstestsScoreboard, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Write a regression report as JSON and Markdown.
pub fn write_regression_report(out_dir: &Path, report: &RegressionReport) -> Result<(), String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("create out dir {}: {e}", out_dir.display()))?;

    let json_path = out_dir.join("regression.json");
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| format!("serialize regression report: {e}"))?;
    std::fs::write(&json_path, json).map_err(|e| format!("write {}: {e}", json_path.display()))?;

    let md_path = out_dir.join("regression.md");
    let mut md = String::new();
    md.push_str("# TideFS xfstests Regression Report\n\n");
    md.push_str(&format!("- **Baseline**: {}\n", report.baseline_range));
    md.push_str(&format!("- **Current**: {}\n\n", report.current_range));

    md.push_str("## Summary\n\n");
    md.push_str("| | Baseline | Current |\n");
    md.push_str("|---|---|---|\n");
    md.push_str(&format!(
        "| Pass | {} | {} |\n",
        report.baseline_summary.passed, report.current_summary.passed
    ));
    md.push_str(&format!(
        "| Fail | {} | {} |\n",
        report.baseline_summary.failed, report.current_summary.failed
    ));
    md.push_str(&format!(
        "| Skip | {} | {} |\n",
        report.baseline_summary.skipped, report.current_summary.skipped
    ));
    md.push_str(&format!(
        "| Diff | {} | {} |\n",
        report.baseline_summary.diff, report.current_summary.diff
    ));
    md.push_str(&format!(
        "| ExpectedFail | {} | {} |\n",
        report.baseline_summary.expected_fail, report.current_summary.expected_fail
    ));
    md.push_str(&format!(
        "| EnvRefusal | {} | {} |\n",
        report.baseline_summary.env_refusal, report.current_summary.env_refusal
    ));
    md.push_str(&format!(
        "| Total | {} | {} |\n\n",
        report.baseline_summary.total, report.current_summary.total
    ));

    if report.has_regressions() {
        md.push_str("## Regressions\n\n");
        for test in &report.regressions {
            md.push_str(&format!("- {test}\n"));
        }
    } else {
        md.push_str("## No Regressions\n\n");
    }

    if !report.improvements.is_empty() {
        md.push_str("\n## Improvements\n\n");
        for test in &report.improvements {
            md.push_str(&format!("- {test}\n"));
        }
    }

    std::fs::write(&md_path, md).map_err(|e| format!("write {}: {e}", md_path.display()))?;

    Ok(())
}

/// Invoke the xfstests harness via the posix daemon subprocess.
///
/// Returns a skip-only scoreboard when the daemon binary or xfstests
/// is unavailable.
pub fn invoke_xfstests_harness(
    daemon_binary: &Path,
    test_range: &str,
    out_dir: &Path,
    quick: bool,
) -> Result<XfstestsScoreboard, String> {
    if !daemon_binary.exists() && !daemon_binary.with_extension("").exists() {
        return produce_skip_scoreboard(test_range, "daemon binary not found");
    }

    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("create out dir {}: {e}", out_dir.display()))?;

    let mut cmd = Command::new(daemon_binary);
    cmd.arg("xfstests-harness");
    cmd.arg("--tests");
    cmd.arg(test_range);
    cmd.arg("--out");
    cmd.arg(out_dir);
    if quick {
        cmd.arg("--quick");
    }

    let output = cmd
        .output()
        .map_err(|e| format!("spawn daemon harness: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If the harness couldn't find xfstests, produce skip scoreboard.
        if stderr.contains("not found") || stderr.contains("No such file") {
            return produce_skip_scoreboard(test_range, "xfstests binary not available");
        }
        return Err(format!(
            "daemon harness exited with {}: {}",
            output.status, stderr
        ));
    }

    let scoreboard_path = out_dir.join("scoreboard.json");
    if scoreboard_path.exists() {
        load_scoreboard(&scoreboard_path)
    } else {
        produce_skip_scoreboard(test_range, "scoreboard.json not produced")
    }
}

fn produce_skip_scoreboard(test_range: &str, reason: &str) -> Result<XfstestsScoreboard, String> {
    let results = expand_test_range(test_range)
        .into_iter()
        .map(|test| ScoreboardEntry {
            test,
            status: TestStatus::Skip,
            duration_secs: None,
            output_diff: None,
            reason: Some(reason.to_string()),
        })
        .collect::<Vec<_>>();

    let summary = ScoreboardSummary {
        total: results.len(),
        passed: 0,
        failed: 0,
        skipped: results.len(),
        diff: 0,
        expected_fail: 0,
        env_refusal: 0,
    };

    Ok(XfstestsScoreboard {
        started_at: "unknown".to_string(),
        duration_secs: 0.0,
        command: "xfstests-harness (skipped)".to_string(),
        test_range: test_range.to_string(),
        results,
        summary,
    })
}

/// Expand a test range like "generic/101-150" into individual test names.
fn expand_test_range(spec: &str) -> Vec<String> {
    let mut results = Vec::new();
    for token in spec.split_whitespace() {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // Split on the last '-' that follows a digit: "generic/101-150"
        if let Some(hyphen_idx) = token.rfind('-') {
            let prefix_end = token[..hyphen_idx].rfind('/').map(|i| i + 1).unwrap_or(0);
            let prefix = &token[..prefix_end];
            let first_str = &token[prefix_end..hyphen_idx];
            let last_str = &token[hyphen_idx + 1..];

            if let (Ok(first), Ok(last)) = (first_str.parse::<u32>(), last_str.parse::<u32>()) {
                if first <= last {
                    let width = first_str.len();
                    for n in first..=last {
                        results.push(format!("{prefix}{n:0width$}"));
                    }
                    continue;
                }
            }
        }
        results.push(token.to_string());
    }
    results
}

// -- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_range_101_150() {
        let tests = expand_test_range("generic/101-150");
        assert_eq!(tests.len(), 50);
        assert_eq!(tests[0], "generic/101");
        assert_eq!(tests[49], "generic/150");
    }

    #[test]
    fn expand_range_051_100() {
        let tests = expand_test_range("generic/051-100");
        assert_eq!(tests.len(), 50);
        assert_eq!(tests[0], "generic/051");
        assert_eq!(tests[49], "generic/100");
    }

    #[test]
    fn expand_range_single() {
        let tests = expand_test_range("generic/101");
        assert_eq!(tests, vec!["generic/101"]);
    }

    #[test]
    fn classification_pass_validation() {
        assert!(TestStatus::Pass.is_pass_validation());
        assert!(!TestStatus::Fail.is_pass_validation());
        assert!(!TestStatus::Skip.is_pass_validation());
        assert!(!TestStatus::Diff.is_pass_validation());
        assert!(!TestStatus::ExpectedFail.is_pass_validation());
        assert!(!TestStatus::EnvironmentRefusal.is_pass_validation());
    }

    #[test]
    fn classification_from_scoreboard_entry() {
        let entry = ScoreboardEntry {
            test: "generic/001".into(),
            status: TestStatus::ExpectedFail,
            duration_secs: None,
            output_diff: None,
            reason: Some("known sparse file limitation".into()),
        };
        let ce = ClassificationEntry::from(entry);
        assert_eq!(ce.classification, XfstestsClassification::ExpectedFail);
        assert!(!ce.classification.is_pass_validation());
        assert!(!ce.classification.is_product_fail());
        assert!(!ce.classification.is_non_validation());
    }

    #[test]
    fn classification_summary() {
        let sb = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/001-005".into(),
            results: vec![
                ScoreboardEntry {
                    test: "generic/001".into(),
                    status: TestStatus::Pass,
                    duration_secs: None,
                    output_diff: None,
                    reason: None,
                },
                ScoreboardEntry {
                    test: "generic/002".into(),
                    status: TestStatus::Fail,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("crash".into()),
                },
                ScoreboardEntry {
                    test: "generic/003".into(),
                    status: TestStatus::ExpectedFail,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("known gap".into()),
                },
                ScoreboardEntry {
                    test: "generic/004".into(),
                    status: TestStatus::Skip,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("not wired".into()),
                },
                ScoreboardEntry {
                    test: "generic/005".into(),
                    status: TestStatus::EnvironmentRefusal,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("no /dev/fuse".into()),
                },
            ],
            summary: ScoreboardSummary {
                total: 5,
                passed: 1,
                failed: 1,
                skipped: 1,
                diff: 0,
                expected_fail: 1,
                env_refusal: 1,
            },
        };
        let cs = sb.classify();
        assert_eq!(cs.counts.pass, 1);
        assert_eq!(cs.counts.fail, 1);
        assert_eq!(cs.counts.expected_fail, 1);
        assert_eq!(cs.counts.skip, 1);
        assert_eq!(cs.counts.env_refusal, 1);
        assert_eq!(cs.counts.total(), 5);
        assert_eq!(cs.counts.passes(), 1);
        assert_eq!(cs.counts.product_failures(), 1);
        assert_eq!(cs.counts.non_validation(), 2);
        assert_eq!(cs.passing_tests().len(), 1);
        assert_eq!(cs.failing_tests().len(), 1);
        assert_eq!(cs.expected_failures().len(), 1);
        assert_eq!(cs.non_validation_entries().len(), 2);
    }

    #[test]
    fn skip_not_treated_as_pass_for_regression() {
        // Skip in baseline -> Fail in current is NOT a regression.
        let base = XfstestsClassification::Skip;
        let curr = XfstestsClassification::Fail;
        assert!(!is_passing_for_regression(base));
        assert!(is_failing_for_regression(curr));
        // The regression detection condition: is_passing(base) && is_failing(curr)
        // Skip is not passing, so this should not produce a regression.
        assert!(!(is_passing_for_regression(base) && is_failing_for_regression(curr)));
    }

    #[test]
    fn regression_detection_pass_to_fail() {
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101-102".into(),
            results: vec![
                ScoreboardEntry {
                    test: "generic/101".into(),
                    status: TestStatus::Pass,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: None,
                },
                ScoreboardEntry {
                    test: "generic/102".into(),
                    status: TestStatus::Pass,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: None,
                },
            ],
            summary: ScoreboardSummary {
                total: 2,
                passed: 2,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101-102".into(),
            results: vec![
                ScoreboardEntry {
                    test: "generic/101".into(),
                    status: TestStatus::Fail,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: Some("failed".into()),
                },
                ScoreboardEntry {
                    test: "generic/102".into(),
                    status: TestStatus::Pass,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: None,
                },
            ],
            summary: ScoreboardSummary {
                total: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };

        let report = compare_scoreboards(&baseline, &current);
        assert!(report.has_regressions());
        assert_eq!(report.regressions, vec!["generic/101"]);
        assert!(report.improvements.is_empty());
    }

    #[test]
    fn regression_detection_improvement() {
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Fail,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: Some("failed".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Pass,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: None,
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };

        let report = compare_scoreboards(&baseline, &current);
        assert!(!report.has_regressions());
        assert_eq!(report.improvements, vec!["generic/101"]);
    }

    #[test]
    fn expected_fail_does_not_cause_regression() {
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::ExpectedFail,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: Some("known sparse file limitation".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 1,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Fail,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: Some("still failing".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let report = compare_scoreboards(&baseline, &current);
        // ExpectedFail -> Fail is NOT a regression (both are non-pass).
        assert!(!report.has_regressions());
        assert!(report.regressions.is_empty());
    }

    #[test]
    fn expected_fail_to_pass_is_improvement() {
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::ExpectedFail,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: Some("known limitation".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 1,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Pass,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: None,
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let report = compare_scoreboards(&baseline, &current);
        assert!(!report.has_regressions());
        assert_eq!(report.improvements, vec!["generic/101"]);
    }

    #[test]
    fn skip_to_fail_is_not_regression() {
        // Skip was never passing validation, so moving to Fail is new information, not a regression.
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Skip,
                duration_secs: Some(0.0),
                output_diff: None,
                reason: Some("not wired".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 0,
                skipped: 1,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Fail,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: Some("now exercised and fails".into()),
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let report = compare_scoreboards(&baseline, &current);
        assert!(!report.has_regressions());
        assert!(report.regressions.is_empty());
        // It's also not an improvement (wasn't failing before).
        assert!(report.improvements.is_empty());
    }

    #[test]
    fn regression_detection_new_tests() {
        let baseline = XfstestsScoreboard {
            started_at: "t0".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Pass,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: None,
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };
        let current = XfstestsScoreboard {
            started_at: "t1".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101-102".into(),
            results: vec![
                ScoreboardEntry {
                    test: "generic/101".into(),
                    status: TestStatus::Pass,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: None,
                },
                ScoreboardEntry {
                    test: "generic/102".into(),
                    status: TestStatus::Pass,
                    duration_secs: Some(1.0),
                    output_diff: None,
                    reason: None,
                },
            ],
            summary: ScoreboardSummary {
                total: 2,
                passed: 2,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };

        let report = compare_scoreboards(&baseline, &current);
        assert!(!report.has_regressions());
        assert_eq!(report.new_tests, vec!["generic/102"]);
    }

    #[test]
    fn scoreboard_roundtrip_json() {
        let sb = XfstestsScoreboard {
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_secs: 1.5,
            command: "xfstests-check -fuse -g quick".into(),
            test_range: "generic/101-150".into(),
            results: vec![ScoreboardEntry {
                test: "generic/101".into(),
                status: TestStatus::Pass,
                duration_secs: Some(1.0),
                output_diff: None,
                reason: None,
            }],
            summary: ScoreboardSummary {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 0,
                env_refusal: 0,
            },
        };

        let json = serde_json::to_string(&sb).unwrap();
        let parsed: XfstestsScoreboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.test_range, "generic/101-150");
        assert_eq!(parsed.summary.total, 1);
    }

    #[test]
    fn scoreboard_roundtrip_with_expected_fail() {
        let sb = XfstestsScoreboard {
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_secs: 1.0,
            command: "check".into(),
            test_range: "generic/101-102".into(),
            results: vec![
                ScoreboardEntry {
                    test: "generic/101".into(),
                    status: TestStatus::ExpectedFail,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("known limitation".into()),
                },
                ScoreboardEntry {
                    test: "generic/102".into(),
                    status: TestStatus::EnvironmentRefusal,
                    duration_secs: None,
                    output_diff: None,
                    reason: Some("no /dev/fuse".into()),
                },
            ],
            summary: ScoreboardSummary {
                total: 2,
                passed: 0,
                failed: 0,
                skipped: 0,
                diff: 0,
                expected_fail: 1,
                env_refusal: 1,
            },
        };
        let json = serde_json::to_string(&sb).unwrap();
        let parsed: XfstestsScoreboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].status, TestStatus::ExpectedFail);
        assert_eq!(parsed.results[1].status, TestStatus::EnvironmentRefusal);
        assert_eq!(parsed.summary.expected_fail, 1);
        assert_eq!(parsed.summary.env_refusal, 1);
    }

    #[test]
    fn xfstests_classification_labels_distinct() {
        let mut seen = std::collections::HashSet::new();
        for c in &[
            XfstestsClassification::Pass,
            XfstestsClassification::Fail,
            XfstestsClassification::ExpectedFail,
            XfstestsClassification::Skip,
            XfstestsClassification::EnvironmentRefusal,
        ] {
            assert!(seen.insert(c.label()), "duplicate label: {}", c.label());
        }
    }

    #[test]
    fn classify_diff_is_fail() {
        assert_eq!(TestStatus::Diff.classify(), XfstestsClassification::Fail);
    }
}
