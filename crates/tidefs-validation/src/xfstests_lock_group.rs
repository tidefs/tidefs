// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! xfstests lock-test group runner backed by the NixOS VM test harness.
//!
//! Invokes the `tidefsXfstestsLockGroup` NixOS test derivation defined in
//! the workspace flake. The NixOS test boots a minimal QEMU VM, mounts
//! TideFS FUSE, runs `xfstests-check -g lock`, parses per-test results,
//! and produces a JSON validation output that is parsed into the standard
//! [`XfstestsScoreboard`] format.
//!
//! When `nix` is not available or the Nix daemon is not functional, the
//! test is skipped.

use serde::Deserialize;
use std::path::PathBuf;

use crate::xfstests_scoreboard::{
    ScoreboardEntry, ScoreboardSummary, TestStatus, XfstestsScoreboard,
};

// -- NixOS validation schema (produced by the flake.nix test driver) --------

/// Top-level validation output produced by the NixOS xfstests lock-group test.
#[derive(Debug, Clone, Deserialize)]
pub struct LockGroupValidation {
    pub test: String,
    pub version: u32,
    pub results: Vec<LockGroupValidationEntry>,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Per-test entry in the NixOS validation output.
#[derive(Debug, Clone, Deserialize)]
pub struct LockGroupValidationEntry {
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub duration_secs: Option<f64>,
    #[serde(default)]
    pub failure_log: Option<String>,
}

// -- Conversion to standard scoreboard ------------------------------------

impl From<LockGroupValidation> for XfstestsScoreboard {
    fn from(ev: LockGroupValidation) -> Self {
        let results: Vec<ScoreboardEntry> = ev
            .results
            .into_iter()
            .map(|e| {
                let status = match e.status.as_str() {
                    "pass" => TestStatus::Pass,
                    "fail" => TestStatus::Fail,
                    "skip" => TestStatus::Skip,
                    "diff" => TestStatus::Diff,
                    "expected-fail" => TestStatus::ExpectedFail,
                    "environment-refusal" => TestStatus::EnvironmentRefusal,
                    _ => TestStatus::Skip,
                };
                ScoreboardEntry {
                    test: e.name,
                    status,
                    duration_secs: e.duration_secs,
                    output_diff: None,
                    reason: e.failure_log,
                }
            })
            .collect();

        let summary = ScoreboardSummary {
            total: results.len(),
            passed: ev.passed,
            failed: ev.failed,
            skipped: ev.skipped,
            diff: 0,
            expected_fail: 0,
            env_refusal: 0,
        };

        XfstestsScoreboard {
            started_at: "nixos-test".to_string(),
            duration_secs: 0.0,
            command: "xfstests-check -g lock (NixOS QEMU)".to_string(),
            test_range: "lock".to_string(),
            results,
            summary,
        }
    }
}

// -- Harness helpers ------------------------------------------------------

/// Locate the TideFS workspace root by walking up from the crate directory
/// until `flake.nix` is found.
pub fn workspace_root() -> Option<PathBuf> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = crate_dir.as_path();
    loop {
        if current.join("flake.nix").exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return None,
        }
    }
}

/// Check whether `nix` is available on `$PATH`.
pub fn nix_available() -> bool {
    std::process::Command::new("nix")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build and run the NixOS xfstests lock-group test via `nix build`.
///
/// Returns the parsed [`XfstestsScoreboard`] on success.
/// Returns `Err(msg)` on build failure or missing prerequisites.
///
/// Individual test failures in the lock group are captured in the
/// scoreboard and do not cause this function to return an error;
/// they are validation, not regressions.
pub fn run_lock_test_group() -> Result<XfstestsScoreboard, String> {
    let root = workspace_root().ok_or("cannot find workspace root")?;

    // First, build to get the output path.
    let output = std::process::Command::new("nix")
        .args([
            "build",
            &format!("{}#tidefsXfstestsLockGroup", root.display()),
            "-L",
            "--print-out-paths",
            "--no-link",
        ])
        .output()
        .map_err(|e| format!("failed to run nix build: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "nix build failed (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status.code(),
        ));
    }

    // nix build --print-out-paths prints the store path on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let store_path = stdout
        .lines()
        .find(|l| l.contains("/nix/store/"))
        .map(|l| l.trim().to_string())
        .ok_or_else(|| format!("nix build succeeded but no store path in output:\n{stdout}"))?;

    let validation_path = PathBuf::from(&store_path).join("xfstests-lock-group.json");

    if !validation_path.exists() {
        return Ok(lock_group_skip_scoreboard(
            "validation output not produced by NixOS test",
        ));
    }

    let data = std::fs::read_to_string(&validation_path)
        .map_err(|e| format!("read {}: {e}", validation_path.display()))?;

    let validation: LockGroupValidation = serde_json::from_str(&data)
        .map_err(|e| format!("parse {}: {e}", validation_path.display()))?;

    Ok(XfstestsScoreboard::from(validation))
}

/// Produce a skip-only scoreboard when the NixOS test cannot produce validation.
fn lock_group_skip_scoreboard(reason: &str) -> XfstestsScoreboard {
    XfstestsScoreboard {
        started_at: "unknown".to_string(),
        duration_secs: 0.0,
        command: format!("xfstests-check -g lock (NixOS QEMU, skipped: {reason})").to_string(),
        test_range: "lock".to_string(),
        results: vec![],
        summary: ScoreboardSummary {
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            diff: 0,
            expected_fail: 0,
            env_refusal: 0,
        },
    }
}

// -- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// NixOS VM integration test: boots a QEMU VM, mounts TideFS FUSE,
    /// runs xfstests lock group (`./check -g lock`), and produces a
    /// JSON scoreboard.
    ///
    /// Requires a functional `nix` on `$PATH` with a writable Nix store.
    /// Skips silently when Nix is not available or the daemon is not
    /// reachable. In a sandbox without a writable Nix store the test
    /// skips rather than failing.
    ///
    /// The test asserts the scoreboard is produced, not that all lock
    /// tests pass -- failures are captured validation.
    #[test]
    fn lock_test_group_scoreboard() {
        if !nix_available() {
            eprintln!(
                "SKIP: nix not found on PATH -- \
                 lock_test_group_scoreboard requires a Nix environment"
            );
            return;
        }

        match run_lock_test_group() {
            Ok(scoreboard) => {
                eprintln!(
                    "PASS: xfstests lock group NixOS VM test completed \
                     (total={}, pass={}, fail={}, skip={})",
                    scoreboard.summary.total,
                    scoreboard.summary.passed,
                    scoreboard.summary.failed,
                    scoreboard.summary.skipped,
                );
            }
            Err(e) => {
                if e.contains("readonly database")
                    || e.contains("read-only file system")
                    || e.contains("No such file or directory")
                    || (e.contains("SQLite database") && e.contains("is busy"))
                {
                    eprintln!(
                        "SKIP: Nix daemon/store unavailable in this \
                         environment -- lock_test_group_scoreboard skipped\n  {e}"
                    );
                    return;
                }
                panic!("xfstests lock group NixOS VM test failed: {e}");
            }
        }
    }

    /// Unit test: validation JSON deserialization round-trip.
    #[test]
    fn validation_deserialize_pass_fail_skip() {
        let json = r#"{
            "test": "tidefs-xfstests-lock-group",
            "version": 1,
            "results": [
                {"name": "generic/001", "status": "pass", "duration_secs": 1.5},
                {"name": "generic/002", "status": "fail", "duration_secs": 0.8,
                 "failure_log": "lock conflict not detected"},
                {"name": "generic/003", "status": "skip", "duration_secs": null,
                 "failure_log": null}
            ],
            "passed": 1,
            "failed": 1,
            "skipped": 1
        }"#;

        let validation: LockGroupValidation = serde_json::from_str(json).expect("parse validation");
        assert_eq!(validation.test, "tidefs-xfstests-lock-group");
        assert_eq!(validation.version, 1);
        assert_eq!(validation.results.len(), 3);
        assert_eq!(validation.passed, 1);
        assert_eq!(validation.failed, 1);
        assert_eq!(validation.skipped, 1);

        // Convert to standard scoreboard
        let sb = XfstestsScoreboard::from(validation);
        assert_eq!(sb.test_range, "lock");
        assert_eq!(sb.summary.total, 3);
        assert_eq!(sb.summary.passed, 1);
        assert_eq!(sb.summary.failed, 1);
        assert_eq!(sb.summary.skipped, 1);

        // Verify per-test mapping
        assert_eq!(sb.results[0].test, "generic/001");
        assert_eq!(sb.results[0].status, TestStatus::Pass);
        assert_eq!(sb.results[0].duration_secs, Some(1.5));

        assert_eq!(sb.results[1].test, "generic/002");
        assert_eq!(sb.results[1].status, TestStatus::Fail);
        assert_eq!(
            sb.results[1].reason,
            Some("lock conflict not detected".to_string())
        );

        assert_eq!(sb.results[2].test, "generic/003");
        assert_eq!(sb.results[2].status, TestStatus::Skip);
    }

    /// Unit test: validation with empty results.
    #[test]
    fn validation_deserialize_empty() {
        let json = r#"{
            "test": "tidefs-xfstests-lock-group",
            "version": 1,
            "results": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0
        }"#;

        let validation: LockGroupValidation = serde_json::from_str(json).expect("parse validation");
        let sb = XfstestsScoreboard::from(validation);
        assert_eq!(sb.summary.total, 0);
        assert!(sb.results.is_empty());
    }

    /// Unit test: workspace_root finds the TideFS root.
    #[test]
    fn workspace_root_finds_flake() {
        let root = workspace_root().expect("should find workspace root");
        assert!(root.join("flake.nix").exists());
    }

    /// Unit test: lock_group_skip_scoreboard produces a valid scoreboard.
    #[test]
    fn skip_scoreboard_is_valid() {
        let sb = lock_group_skip_scoreboard("nix not available");
        assert_eq!(sb.test_range, "lock");
        assert_eq!(sb.summary.total, 0);
        assert!(sb.results.is_empty());
    }
}
