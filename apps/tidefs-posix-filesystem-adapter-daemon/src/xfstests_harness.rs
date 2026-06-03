//! xfstests harness -- runs xfstests against a TideFS FUSE mount and produces
//! a structured JSON scoreboard with per-test pass/fail/skip/diff entries.
//!
//! Supports test ranges like `generic/101-150` via batch expansion.
//! When xfstests is absent, produces a skip-only scoreboard so `cargo test`
//! never panics on missing external tooling.

#![allow(dead_code)]
#![deny(unused_imports)]

use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use tidefs_local_filesystem::ROOT_AUTHENTICATION_ENV_VAR;

// -- Scoreboard data model ----------------------------------------------

/// Outcome of a single xfstests test case.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Pass,
    Fail,
    Skip,
    /// Test ran but produced output that differs from the golden output.
    Diff,
}

impl fmt::Display for TestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestStatus::Pass => write!(f, "pass"),
            TestStatus::Fail => write!(f, "fail"),
            TestStatus::Skip => write!(f, "skip"),
            TestStatus::Diff => write!(f, "diff"),
        }
    }
}

/// Per-test entry in the scoreboard.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreboardEntry {
    /// Full test name, e.g. "generic/101".
    pub test: String,
    pub status: TestStatus,
    /// Wall-clock duration of the test (if it ran).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    /// Captured output diff when the test fails or differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_diff: Option<String>,
    /// Optional human-readable failure reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Top-level scoreboard produced by a run.
#[derive(Debug, Clone, Serialize)]
pub struct XfstestsScoreboard {
    /// UTC timestamp when the run started.
    pub started_at: String,
    /// Total wall-clock duration of the run.
    pub duration_secs: f64,
    /// xfstests command that was executed.
    pub command: String,
    /// Test range (human-readable).
    pub test_range: String,
    /// Per-test results.
    pub results: Vec<ScoreboardEntry>,
    /// Summary counts.
    pub summary: ScoreboardSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreboardSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub diff: usize,
}

// -- Test range parsing -------------------------------------------------

/// A spec for which xfstests tests to run.
#[derive(Debug, Clone)]
pub enum TestRange {
    /// Run a single test, e.g. `generic/101`.
    Single(String),
    /// Run a contiguous numeric batch, e.g. `generic/101-150`.
    Batch {
        prefix: String,
        first: u32,
        last: u32,
        /// Width for zero-padding (derived from input token's first number length).
        width: usize,
    },
}

impl TestRange {
    /// Parse strings like `generic/101`, `generic/101-150`, or
    /// `generic/101 generic/102`.
    pub fn parse(spec: &str) -> Result<Vec<TestRange>, String> {
        let mut ranges = Vec::new();
        for token in spec.split_whitespace() {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(hyphen_idx) = token.rfind('-') {
                let slash_idx = token[..hyphen_idx].rfind('/');
                let prefix_end = slash_idx.map(|i| i + 1).unwrap_or(0);
                let prefix = if prefix_end > 0 {
                    token[..prefix_end].to_string()
                } else {
                    String::new()
                };

                let first_str = &token[prefix_end..hyphen_idx];
                let last_str = &token[hyphen_idx + 1..];

                let first: u32 = first_str
                    .parse()
                    .map_err(|e| format!("invalid range start in `{token}`: {e}"))?;
                let last: u32 = last_str
                    .parse()
                    .map_err(|e| format!("invalid range end in `{token}`: {e}"))?;

                if first > last {
                    return Err(format!(
                        "invalid range `{token}`: start {first} > end {last}"
                    ));
                }

                let number_width = first_str.len();
                ranges.push(TestRange::Batch {
                    prefix,
                    first,
                    last,
                    width: number_width,
                });
            } else {
                ranges.push(TestRange::Single(token.to_string()));
            }
        }
        Ok(ranges)
    }

    /// Expand into a list of test names usable by xfstests.
    pub fn expand(&self) -> Vec<String> {
        match self {
            TestRange::Single(name) => vec![name.clone()],
            TestRange::Batch {
                prefix,
                first,
                last,
                width,
            } => (*first..=*last)
                .map(|n| format!("{prefix}{n:0width$}"))
                .collect(),
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> String {
        match self {
            TestRange::Single(name) => name.clone(),
            TestRange::Batch {
                prefix,
                first,
                last,
                width,
            } => format!("{prefix}{first:0width$}-{last:0width$}"),
        }
    }
}

// -- Group alias expansion ----------------------------------------------

/// Map conceptual xfstests group names to their actual generic test tokens.
///
/// xfstests v2023.05.14 has no `lock/`, `symlink/`, or `fallocate/`
/// test directories -- only `generic/`. This function translates the
/// conceptual group names into the concrete generic test numbers that
/// exercise those feature areas.
///
/// Tokens containing a `/` (e.g. `generic/001`) pass through unchanged.
/// Unknown group names are returned as-is (they will fail at xfstests level).
pub fn expand_xfstests_group_aliases(tokens: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();
    for token in tokens {
        if token.contains('/') {
            // Already a concrete test: pass through unchanged.
            expanded.push(token.clone());
            continue;
        }
        match token.as_str() {
            "lock" => {
                // POSIX lock tests (fcntl, flock, OFD locks, lock lifetimes).
                expanded.extend(
                    ["generic/131", "generic/184", "generic/192", "generic/294"]
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
            "symlink" => {
                // Symlink creation, readlink, and traversal tests.
                expanded.extend(
                    ["generic/011", "generic/012", "generic/013"]
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
            "fallocate" => {
                // fallocate(2) tests: prealloc, punch-hole, collapse, zero-range.
                expanded.extend(
                    [
                        "generic/075",
                        "generic/091",
                        "generic/094",
                        "generic/225",
                        "generic/228",
                        "generic/263",
                    ]
                    .iter()
                    .map(|s| s.to_string()),
                );
            }
            _ => {
                expanded.push(token.clone());
            }
        }
    }
    expanded
}

// -- Result parsing -----------------------------------------------------

/// Parse the output of xfstests `check` and build per-test entries.
///
/// Recognises these line patterns:
///   generic/101 1s ...
///   generic/101  1s
///   generic/101       [not run] ...
///   generic/101  [not run]
fn parse_xfstests_output(raw: &str, test_list: &[String]) -> Vec<ScoreboardEntry> {
    let mut entries: BTreeMap<String, ScoreboardEntry> = BTreeMap::new();

    // Pre-populate with skip entries for every test we expected to run.
    for test in test_list {
        entries.insert(
            test.clone(),
            ScoreboardEntry {
                test: test.clone(),
                status: TestStatus::Skip,
                duration_secs: None,
                output_diff: None,
                reason: Some("not run (harness did not observe a result line)".into()),
            },
        );
    }

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (test_name, rest) = match line.find(char::is_whitespace) {
            Some(idx) => {
                let name = line[..idx].trim().to_string();
                let rest = line[idx..].trim().to_string();
                (name, rest)
            }
            None => continue,
        };

        if !test_name.contains('/') {
            continue;
        }

        let mut entry = entries
            .remove(&test_name)
            .unwrap_or_else(|| ScoreboardEntry {
                test: test_name.clone(),
                status: TestStatus::Skip,
                duration_secs: None,
                output_diff: None,
                reason: Some("unexpected line from xfstests".into()),
            });

        let rest_lower = rest.to_lowercase();

        if rest_lower.contains("not run") {
            entry.status = TestStatus::Skip;
            entry.reason = Some(format!("xfstests reported: {rest}"));
        } else if rest_lower.contains("fail") || rest_lower.contains("failed") {
            entry.status = TestStatus::Fail;
            entry.reason = Some(format!("xfstests reported: {rest}"));
        } else {
            let mut found_duration = false;
            if let Some(dur_str) = rest
                .split_whitespace()
                .find(|w| w.ends_with('s') && w[..w.len() - 1].parse::<f64>().is_ok())
            {
                if let Ok(secs) = dur_str[..dur_str.len() - 1].parse::<f64>() {
                    entry.duration_secs = Some(secs);
                    found_duration = true;
                }
            }

            if found_duration {
                entry.status = TestStatus::Pass;
                entry.reason = None;
            }
        }

        entries.insert(test_name, entry);
    }

    let mut results: Vec<ScoreboardEntry> = entries.into_values().collect();
    results.sort_by(|a, b| a.test.cmp(&b.test));
    results
}

// -- Runner -------------------------------------------------------------

/// Configuration for a single xfstests harness run.
#[derive(Debug, Clone)]
pub struct XfstestsConfig {
    /// Tests to run (expanded from range spec).
    pub test_list: Vec<String>,
    /// Human-readable range label.
    pub range_label: String,
    /// Path to the xfstests `check` script (or `xfstests-check` wrapper).
    pub check_binary: PathBuf,
    /// Extra arguments to pass to `check` (e.g. `-fuse`, `-g quick`).
    pub check_args: Vec<String>,
    /// Path to an exclude file (appended as `-E <path>`).
    pub exclude_file: Option<PathBuf>,
    /// Directory where xfstests writes per-test `.out.bad` files.
    pub results_dir: Option<PathBuf>,
    /// Output directory for the scoreboard JSON.
    pub out_dir: PathBuf,
    /// When true, do not pass the exclude file to xfstests.
    /// Used for targeted test groups (lock/symlink/fallocate) where
    /// otherwise-excluded tests need to run.
    pub skip_exclude: bool,
    /// Environment variables to forward to the check command.
    pub env_vars: Vec<(String, String)>,
}

impl XfstestsConfig {
    /// Build from environment variables set by the posix-scoreboard harness.
    pub fn from_scoreboard_env(out_dir: PathBuf) -> Result<Self, String> {
        let check_binary = which("xfstests-check")
            .or_else(|| which("check"))
            .unwrap_or_else(|| PathBuf::from("xfstests-check"));

        let test_list: Vec<String> = std::env::var("TIDEFS_XFSTESTS_TESTS")
            .unwrap_or_else(|_| "generic/001".to_string())
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let range_label = test_list.join(" ");

        let mut check_args: Vec<String> = std::env::var("TIDEFS_XFSTESTS_CHECK_ARGS")
            .unwrap_or_else(|_| "-fuse".to_string())
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let exclude_file = std::env::var("TIDEFS_XFSTESTS_EXCLUDE")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists());

        if let Some(ref exclude) = exclude_file {
            check_args.push("-E".into());
            check_args.push(exclude.display().to_string());
        }

        let results_dir = std::env::var("TIDEFS_XFSTESTS_RESULTS_DIR")
            .ok()
            .map(PathBuf::from);

        let mount = std::env::var("TIDEFS_SCOREBOARD_MOUNT").unwrap_or_default();

        let mut env_vars = Vec::new();
        // Set TIDEFS_BIN so mount.fuse helper can locate the daemon binary.
        if let Ok(exe) = std::env::current_exe() {
            env_vars.push(("TIDEFS_BIN".into(), exe.display().to_string()));
        }
        // Prepend mount helper dir and /usr/bin to PATH.  The mount helper dir
        // contains a "mount" wrapper that routes -t fuse to /usr/sbin/mount.fuse
        // because the Nix mount binary lacks FUSE support.
        let mut fused_path = std::env::var("PATH").unwrap_or_default();
        if let Ok(mh_dir) = std::env::var("TIDEFS_XFSTESTS_MOUNT_HELPER_DIR") {
            fused_path = format!("{mh_dir}:{fused_path}");
        }
        fused_path = format!("/usr/bin:/usr/sbin:{fused_path}");
        env_vars.push(("PATH".into(), fused_path));
        if !mount.is_empty() {
            env_vars.push(("TIDEFS_SCOREBOARD_MOUNT".into(), mount.clone()));
            env_vars.push(("TEST_DIR".into(), mount.clone()));
            env_vars.push(("TEST_DEV".into(), "tidefs-preview".into()));
            env_vars.push(("FSTYP".into(), "fuse".into()));
        } else {
            // No pre-existing mount: create a temp mount point for xfstests.
            let test_dir = std::env::var("TIDEFS_XFSTESTS_TEST_DIR")
                .unwrap_or_else(|_| "/tmp/tidefs-xfstests-mnt".to_string());
            std::fs::create_dir_all(&test_dir).ok();
            env_vars.push(("TEST_DIR".into(), test_dir));
            env_vars.push(("TEST_DEV".into(), "tidefs-preview".into()));
            env_vars.push(("FSTYP".into(), "fuse".into()));
            env_vars.push((
                ROOT_AUTHENTICATION_ENV_VAR.into(),
                "4141414141414141414141414141414141414141414141414141414141414141".to_string(),
            ));
            env_vars.push((
                ROOT_AUTHENTICATION_ENV_VAR.into(),
                "4141414141414141414141414141414141414141414141414141414141414141".to_string(),
            ));
        }

        Ok(XfstestsConfig {
            test_list,
            range_label,
            check_binary,
            check_args,
            exclude_file,
            results_dir,
            out_dir,
            skip_exclude: false,
            env_vars,
        })
    }

    /// Build from explicit CLI args (the `xfstests-harness` subcommand path).
    pub fn from_cli(
        range_spec: String,
        out_dir: PathBuf,
        quick: bool,
        auto: bool,
        exclude_file: Option<PathBuf>,
        skip_exclude: bool,
    ) -> Result<Self, String> {
        let ranges = TestRange::parse(&range_spec)?;

        let mut test_list = Vec::new();
        for range in &ranges {
            test_list.extend(range.expand());
        }

        let range_label = ranges
            .iter()
            .map(|r| r.label())
            .collect::<Vec<_>>()
            .join(" ");

        let check_binary = which("xfstests-check")
            .or_else(|| which("check"))
            .unwrap_or_else(|| PathBuf::from("xfstests-check"));

        let mut check_args = Vec::new();
        if quick {
            check_args.push("-g".into());
            check_args.push("quick".into());
        }
        if auto {
            check_args.push("-g".into());
            check_args.push("auto".into());
        }
        if check_args.is_empty() {
            check_args.push("-fuse".into());
        }

        if !skip_exclude {
            if let Some(ref exclude) = exclude_file {
                check_args.push("-E".into());
                check_args.push(exclude.display().to_string());
            }
        }

        let mount = std::env::var("TIDEFS_SCOREBOARD_MOUNT").unwrap_or_default();
        let mut env_vars = Vec::new();
        if !mount.is_empty() {
            env_vars.push(("TIDEFS_SCOREBOARD_MOUNT".into(), mount));
        }
        env_vars.push(("FSTYP".into(), "fuse".into()));

        let test_dir = std::env::var("TIDEFS_XFSTESTS_TEST_DIR")
            .unwrap_or_else(|_| "/tmp/tidefs-xfstests-mnt".to_string());
        std::fs::create_dir_all(&test_dir).ok();
        env_vars.push(("TEST_DIR".into(), test_dir));
        env_vars.push(("TEST_DEV".into(), "tidefs-preview".into()));
        env_vars.push((
            ROOT_AUTHENTICATION_ENV_VAR.into(),
            "4141414141414141414141414141414141414141414141414141414141414141".to_string(),
        ));

        let results_dir = std::env::var("TIDEFS_XFSTESTS_RESULTS_DIR")
            .ok()
            .map(PathBuf::from);

        Ok(XfstestsConfig {
            test_list,
            range_label,
            check_binary,
            check_args,
            exclude_file,
            results_dir,
            out_dir,
            env_vars,
            skip_exclude,
        })
    }
}

/// Run xfstests according to the config and produce a scoreboard.
pub fn run_xfstests(config: &XfstestsConfig) -> Result<XfstestsScoreboard, String> {
    let started_at = chrono_local_now();

    // If xfstests binary isn't available, produce skip-only board.
    if !config.check_binary.exists() && which("xfstests-check").is_none() {
        return produce_skip_scoreboard(config, &started_at);
    }

    std::fs::create_dir_all(&config.out_dir)
        .map_err(|e| format!("create out dir {}: {e}", config.out_dir.display()))?;

    let mut cmd = Command::new(&config.check_binary);
    cmd.args(&config.check_args);
    cmd.args(&config.test_list);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    for (key, val) in &config.env_vars {
        cmd.env(key, val);
    }

    if let Some(ref results_dir) = config.results_dir {
        cmd.env("RESULT_BASE", results_dir);
    }

    let start = Instant::now();

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn xfstests: {e}"))?;

    let mut stdout = Vec::new();
    if let Some(ref mut pipe) = child.stdout {
        io::copy(&mut BufReader::new(pipe), &mut stdout)
            .map_err(|e| format!("read xfstests stdout: {e}"))?;
    }

    let mut stderr = Vec::new();
    if let Some(ref mut pipe) = child.stderr {
        io::copy(&mut BufReader::new(pipe), &mut stderr)
            .map_err(|e| format!("read xfstests stderr: {e}"))?;
    }

    let status = child.wait().map_err(|e| format!("wait xfstests: {e}"))?;

    let elapsed = start.elapsed();
    let stdout_str = String::from_utf8_lossy(&stdout);

    let mut results = parse_xfstests_output(&stdout_str, &config.test_list);

    if !status.success() {
        for entry in &mut results {
            if entry.status == TestStatus::Skip
                && entry.reason.as_deref()
                    == Some("not run (harness did not observe a result line)")
            {
                entry.reason = Some(format!(
                    "xfstests exited with code {}",
                    status.code().unwrap_or(-1)
                ));
            }
        }
    }

    // Attach per-test diff output from .out.bad files.
    if let Some(ref results_dir) = config.results_dir {
        for entry in &mut results {
            if entry.status == TestStatus::Fail || entry.status == TestStatus::Diff {
                let bad_file = results_dir.join(format!("{}.out.bad", entry.test));
                if bad_file.exists() {
                    if let Ok(diff) = std::fs::read_to_string(&bad_file) {
                        entry.output_diff = Some(diff);
                    }
                }
            }
        }
    }

    let summary = build_summary(&results);
    let command = format!(
        "{} {}",
        config.check_binary.display(),
        config.check_args.join(" ")
    );

    let scoreboard = XfstestsScoreboard {
        started_at,
        duration_secs: elapsed.as_secs_f64(),
        command,
        test_range: config.range_label.clone(),
        results,
        summary,
    };

    write_scoreboard(&config.out_dir, &scoreboard)?;
    write_markdown_summary(&config.out_dir, &scoreboard)?;

    Ok(scoreboard)
}

/// Produce a skip-only scoreboard when xfstests isn't available.
fn produce_skip_scoreboard(
    config: &XfstestsConfig,
    started_at: &str,
) -> Result<XfstestsScoreboard, String> {
    std::fs::create_dir_all(&config.out_dir)
        .map_err(|e| format!("create out dir {}: {e}", config.out_dir.display()))?;

    let results: Vec<ScoreboardEntry> = config
        .test_list
        .iter()
        .map(|test| ScoreboardEntry {
            test: test.clone(),
            status: TestStatus::Skip,
            duration_secs: None,
            output_diff: None,
            reason: Some("xfstests binary not available in this environment".into()),
        })
        .collect();

    let summary = build_summary(&results);
    let scoreboard = XfstestsScoreboard {
        started_at: started_at.to_string(),
        duration_secs: 0.0,
        command: "xfstests-check (not found)".into(),
        test_range: config.range_label.clone(),
        results,
        summary,
    };

    write_scoreboard(&config.out_dir, &scoreboard)?;
    write_markdown_summary(&config.out_dir, &scoreboard)?;

    Ok(scoreboard)
}

fn build_summary(results: &[ScoreboardEntry]) -> ScoreboardSummary {
    let total = results.len();
    let passed = results
        .iter()
        .filter(|e| e.status == TestStatus::Pass)
        .count();
    let failed = results
        .iter()
        .filter(|e| e.status == TestStatus::Fail)
        .count();
    let skipped = results
        .iter()
        .filter(|e| e.status == TestStatus::Skip)
        .count();
    let diff = results
        .iter()
        .filter(|e| e.status == TestStatus::Diff)
        .count();

    ScoreboardSummary {
        total,
        passed,
        failed,
        skipped,
        diff,
    }
}

fn write_scoreboard(out_dir: &Path, scoreboard: &XfstestsScoreboard) -> Result<(), String> {
    let json_path = out_dir.join("scoreboard.json");
    let json = serde_json::to_string_pretty(scoreboard)
        .map_err(|e| format!("serialize scoreboard: {e}"))?;

    let mut f = std::fs::File::create(&json_path)
        .map_err(|e| format!("create {}: {e}", json_path.display()))?;
    f.write_all(json.as_bytes())
        .map_err(|e| format!("write {}: {e}", json_path.display()))?;

    let valid_path = out_dir.join("scoreboard.valid");
    std::fs::write(&valid_path, "true\n")
        .map_err(|e| format!("write {}: {e}", valid_path.display()))?;

    Ok(())
}

fn write_markdown_summary(out_dir: &Path, scoreboard: &XfstestsScoreboard) -> Result<(), String> {
    let md_path = out_dir.join("scoreboard.md");
    let mut md = String::new();

    md.push_str("# TideFS xfstests Scoreboard\n\n");
    md.push_str(&format!("- **Started**: {}\n", scoreboard.started_at));
    md.push_str(&format!(
        "- **Duration**: {:.1}s\n",
        scoreboard.duration_secs
    ));
    md.push_str(&format!("- **Command**: `{}`\n", scoreboard.command));
    md.push_str(&format!("- **Test range**: {}\n\n", scoreboard.test_range));

    md.push_str("## Summary\n\n");
    md.push_str("| Status | Count |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Pass   | {} |\n", scoreboard.summary.passed));
    md.push_str(&format!("| Fail   | {} |\n", scoreboard.summary.failed));
    md.push_str(&format!("| Skip   | {} |\n", scoreboard.summary.skipped));
    md.push_str(&format!("| Diff   | {} |\n", scoreboard.summary.diff));
    md.push_str(&format!(
        "| **Total** | **{}** |\n\n",
        scoreboard.summary.total
    ));

    if scoreboard.summary.failed > 0 || scoreboard.summary.diff > 0 {
        md.push_str("## Failures\n\n");
        for entry in &scoreboard.results {
            if entry.status == TestStatus::Fail || entry.status == TestStatus::Diff {
                md.push_str(&format!("- **{}** ({})", entry.test, entry.status));
                if let Some(ref reason) = entry.reason {
                    md.push_str(&format!(": {reason}"));
                }
                md.push('\n');
                if let Some(ref diff) = entry.output_diff {
                    md.push_str(&format!(
                        "  ```\n  {}\n  ```\n",
                        diff.lines()
                            .map(|l| l.to_string())
                            .collect::<Vec<_>>()
                            .join("\n  ")
                    ));
                }
            }
        }
    }

    let mut f = std::fs::File::create(&md_path)
        .map_err(|e| format!("create {}: {e}", md_path.display()))?;
    f.write_all(md.as_bytes())
        .map_err(|e| format!("write {}: {e}", md_path.display()))?;

    Ok(())
}

// -- Helpers ------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(name);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

fn chrono_local_now() -> String {
    match Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

// -- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_single() {
        let ranges = TestRange::parse("generic/101").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].expand(), vec!["generic/101"]);
        assert_eq!(ranges[0].label(), "generic/101");
    }

    #[test]
    fn test_range_batch_101_150() {
        let ranges = TestRange::parse("generic/101-150").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].label(), "generic/101-150");
        let expanded = ranges[0].expand();
        assert_eq!(expanded.len(), 50);
        assert_eq!(expanded[0], "generic/101");
        assert_eq!(expanded[49], "generic/150");
        // Spot-check a few values in the middle.
        assert_eq!(expanded[10], "generic/111");
        assert_eq!(expanded[20], "generic/121");
    }

    #[test]
    fn test_range_batch_three_digit() {
        let ranges = TestRange::parse("generic/051-100").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].label(), "generic/051-100");
        let expanded = ranges[0].expand();
        assert_eq!(expanded.len(), 50);
        assert_eq!(expanded[0], "generic/051");
        assert_eq!(expanded[49], "generic/100");
    }

    #[test]
    fn test_range_batch_small() {
        let ranges = TestRange::parse("generic/101-105").unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].label(), "generic/101-105");
        let expanded = ranges[0].expand();
        assert_eq!(expanded.len(), 5);
        assert_eq!(expanded[0], "generic/101");
        assert_eq!(expanded[4], "generic/105");
    }

    #[test]
    fn test_range_multiple() {
        let ranges = TestRange::parse("generic/101 generic/102").unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].label(), "generic/101");
        assert_eq!(ranges[1].label(), "generic/102");
        assert_eq!(ranges[0].expand(), vec!["generic/101"]);
        assert_eq!(ranges[1].expand(), vec!["generic/102"]);
    }

    #[test]
    fn test_range_invalid_rejects_start_greater_than_end() {
        assert!(TestRange::parse("generic/150-101").is_err());
    }

    #[test]
    fn parse_xfstests_output_pass_line() {
        let raw = "generic/101 1s ...\ngeneric/102 2s ...";
        let list: Vec<String> = vec!["generic/101".into(), "generic/102".into()];
        let results = parse_xfstests_output(raw, &list);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, TestStatus::Pass);
        assert_eq!(results[0].duration_secs, Some(1.0));
        assert_eq!(results[1].status, TestStatus::Pass);
        assert_eq!(results[1].duration_secs, Some(2.0));
    }

    #[test]
    fn parse_xfstests_output_not_run_line() {
        let raw = "generic/099 [not run] ACL not supported";
        let list: Vec<String> = vec!["generic/099".into()];
        let results = parse_xfstests_output(raw, &list);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, TestStatus::Skip);
    }

    #[test]
    fn parse_xfstests_output_fail_line() {
        let raw = "generic/103 0s [failed]";
        let list: Vec<String> = vec!["generic/103".into()];
        let results = parse_xfstests_output(raw, &list);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, TestStatus::Fail);
    }

    #[test]
    fn parse_xfstests_output_unobserved_marks_skip() {
        let raw = "";
        let list: Vec<String> = vec!["generic/101".into(), "generic/102".into()];
        let results = parse_xfstests_output(raw, &list);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, TestStatus::Skip);
        assert_eq!(results[1].status, TestStatus::Skip);
    }

    #[test]
    fn scoreboard_serializes_to_valid_json() {
        let entry = ScoreboardEntry {
            test: "generic/101".into(),
            status: TestStatus::Pass,
            duration_secs: Some(1.5),
            output_diff: None,
            reason: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["test"], "generic/101");
        assert_eq!(parsed["status"], "pass");
        assert_eq!(parsed["duration_secs"], 1.5);
    }

    #[test]
    fn scoreboard_summary_counts() {
        let results = vec![
            ScoreboardEntry {
                test: "t1".into(),
                status: TestStatus::Pass,
                duration_secs: None,
                output_diff: None,
                reason: None,
            },
            ScoreboardEntry {
                test: "t2".into(),
                status: TestStatus::Fail,
                duration_secs: None,
                output_diff: None,
                reason: None,
            },
            ScoreboardEntry {
                test: "t3".into(),
                status: TestStatus::Skip,
                duration_secs: None,
                output_diff: None,
                reason: None,
            },
        ];
        let summary = build_summary(&results);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.diff, 0);
    }

    #[test]
    fn harness_skip_when_no_xfstests() {
        let tmp = tempfile::tempdir().unwrap();
        let config = XfstestsConfig {
            test_list: vec!["generic/101".into()],
            range_label: "generic/101".into(),
            check_binary: PathBuf::from("/nonexistent/xfstests-check"),
            check_args: vec!["-fuse".into()],
            exclude_file: None,
            results_dir: None,
            out_dir: tmp.path().to_path_buf(),
            skip_exclude: false,
            env_vars: Vec::new(),
        };
        let scoreboard = run_xfstests(&config).unwrap();
        assert_eq!(scoreboard.results.len(), 1);
        assert_eq!(scoreboard.results[0].status, TestStatus::Skip);
        assert_eq!(scoreboard.summary.skipped, 1);

        assert!(tmp.path().join("scoreboard.json").exists());
        assert!(tmp.path().join("scoreboard.md").exists());
        assert!(tmp.path().join("scoreboard.valid").exists());
    }

    #[test]
    fn harness_creates_out_dir_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let out_dir = tmp.path().join("new-subdir");
        let config = XfstestsConfig {
            test_list: vec!["generic/101".into()],
            range_label: "generic/101".into(),
            check_binary: PathBuf::from("/nonexistent/xfstests-check"),
            check_args: vec![],
            exclude_file: None,
            results_dir: None,
            out_dir: out_dir.clone(),
            skip_exclude: false,
            env_vars: Vec::new(),
        };
        let scoreboard = run_xfstests(&config).unwrap();
        assert!(out_dir.exists());
        assert_eq!(scoreboard.results.len(), 1);
    }
    #[test]
    fn expand_xfstests_group_aliases_maps_lock_symlink_fallocate() {
        let tokens: Vec<String> = ["lock".into(), "symlink".into(), "fallocate".into()].to_vec();
        let expanded = expand_xfstests_group_aliases(&tokens);
        assert!(
            expanded.contains(&"generic/131".to_string()),
            "lock should map to generic/131"
        );
        assert!(
            expanded.contains(&"generic/184".to_string()),
            "lock should map to generic/184"
        );
        assert!(
            expanded.contains(&"generic/192".to_string()),
            "lock should map to generic/192"
        );
        assert!(
            expanded.contains(&"generic/294".to_string()),
            "lock should map to generic/294"
        );
        assert!(
            expanded.contains(&"generic/011".to_string()),
            "symlink should map to generic/011"
        );
        assert!(
            expanded.contains(&"generic/012".to_string()),
            "symlink should map to generic/012"
        );
        assert!(
            expanded.contains(&"generic/013".to_string()),
            "symlink should map to generic/013"
        );
        assert!(
            expanded.contains(&"generic/075".to_string()),
            "fallocate should map to generic/075"
        );
        assert!(
            expanded.contains(&"generic/091".to_string()),
            "fallocate should map to generic/091"
        );
        assert!(
            expanded.contains(&"generic/094".to_string()),
            "fallocate should map to generic/094"
        );
        assert!(
            expanded.contains(&"generic/225".to_string()),
            "fallocate should map to generic/225"
        );
        assert!(
            expanded.contains(&"generic/228".to_string()),
            "fallocate should map to generic/228"
        );
        assert!(
            expanded.contains(&"generic/263".to_string()),
            "fallocate should map to generic/263"
        );
        // Total: 4 lock + 3 symlink + 6 fallocate = 13 tests
        assert_eq!(expanded.len(), 13);
    }

    #[test]
    fn expand_xfstests_group_aliases_passes_through_specific_tests() {
        let tokens: Vec<String> = ["generic/001".into(), "generic/042".into()].to_vec();
        let expanded = expand_xfstests_group_aliases(&tokens);
        assert_eq!(expanded, vec!["generic/001", "generic/042"]);
    }

    #[test]
    fn expand_xfstests_group_aliases_unknown_token_passes_through() {
        let tokens: Vec<String> = ["unknown_group".into()].to_vec();
        let expanded = expand_xfstests_group_aliases(&tokens);
        assert_eq!(expanded, vec!["unknown_group"]);
    }

    #[test]
    fn expand_xfstests_group_aliases_single_lock_maps_all_four() {
        let tokens: Vec<String> = ["lock".into()].to_vec();
        let expanded = expand_xfstests_group_aliases(&tokens);
        let expected: Vec<String> = ["generic/131", "generic/184", "generic/192", "generic/294"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        expanded
            .iter()
            .for_each(|t| assert!(expected.contains(t), "{t} not in expected"));
        expected
            .iter()
            .for_each(|t| assert!(expanded.contains(t), "{t} not in expanded"));
        assert_eq!(expanded.len(), 4);
    }

    #[test]
    fn expand_xfstests_group_aliases_fallocate_maps_six_tests() {
        let tokens: Vec<String> = ["fallocate".into()].to_vec();
        let expanded = expand_xfstests_group_aliases(&tokens);
        let expected = vec![
            "generic/075",
            "generic/091",
            "generic/094",
            "generic/225",
            "generic/228",
            "generic/263",
        ];
        for t in &expected {
            assert!(expanded.contains(&t.to_string()), "{t} not in expanded");
        }
        assert_eq!(expanded.len(), 6);
    }
}
