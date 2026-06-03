//! check-trace-oracle gate for tidefs-xtask.
//!
//! Validates the `tidefs-trace-oracle` crate and the golden trace corpus by
//! running crate tests and replaying all pool traces from `traces/MANIFEST.json`.

use std::path::PathBuf;
use std::process::Command;

use tidefs_trace_oracle::manifest::{load_manifest, print_results, verify_trace_corpus};

/// Run the full check-trace-oracle gate.
///
/// 1. Runs `cargo test -p tidefs-trace-oracle`.
/// 2. Loads `traces/MANIFEST.json`.
/// 3. Replays all pool traces through `verify_trace_corpus`.
/// 4. Reports per-trace PASS/FAIL and exits non-zero on failure.
pub fn check_trace_oracle_current_workspace() -> Result<(), String> {
    let repo_root = find_repo_root()?;

    // Step 1: run crate unit tests.
    let test_status = Command::new("cargo")
        .args(["test", "-p", "tidefs-trace-oracle"])
        .current_dir(&repo_root)
        .status()
        .map_err(|e| format!("cargo test failed to start: {e}"))?;

    if !test_status.success() {
        return Err("cargo test -p tidefs-trace-oracle failed".into());
    }

    // Step 2: load manifest.
    let manifest_path = repo_root.join("traces").join("MANIFEST.json");
    if !manifest_path.exists() {
        return Err(format!(
            "MANIFEST.json not found at {}",
            manifest_path.display()
        ));
    }

    let manifest =
        load_manifest(&manifest_path).map_err(|e| format!("failed to load manifest: {e}"))?;

    if manifest.manifest_version != 1 {
        return Err(format!(
            "unsupported manifest_version: {}",
            manifest.manifest_version
        ));
    }

    // Step 3: replay corpus.
    let results = verify_trace_corpus(&repo_root, &manifest)
        .map_err(|e| format!("verify_trace_corpus failed: {e}"))?;

    print_results(&results);

    let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    if !failures.is_empty() {
        return Err(format!("{} trace(s) failed", failures.len()));
    }

    Ok(())
}

fn find_repo_root() -> Result<PathBuf, String> {
    // Walk up from current directory to find Cargo.toml with workspace.
    let mut dir = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            // Verify it's the workspace root.
            let contents = std::fs::read_to_string(&cargo_toml)
                .map_err(|e| format!("read Cargo.toml: {e}"))?;
            if contents.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            return Err("could not find workspace root".into());
        }
    }
}
