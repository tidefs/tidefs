// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! check-trace-oracle gate for tidefs-xtask.
//!
//! Validates the `tidefs-trace-oracle` crate and the golden trace corpus by
//! running crate tests and replaying all pool traces from `traces/MANIFEST.json`.

use std::path::{Path, PathBuf};
use std::process::Command;

use tidefs_trace_oracle::artifact_manifest::{
    default_manifest_path, generated_at_now_utc, sanitize_artifact_id, ArtifactRunResult,
    TraceArtifactManifest, TRACE_ARTIFACT_BACKEND_COMPARE,
};
use tidefs_trace_oracle::backend::{compare_model_and_runtime_trace, BACKEND_MODEL};
use tidefs_trace_oracle::manifest::{load_manifest, print_results, verify_trace_corpus};

/// Run the full check-trace-oracle gate.
///
/// 1. Runs `cargo test -p tidefs-trace-oracle`.
/// 2. Loads `traces/MANIFEST.json`.
/// 3. Replays all pool traces through `verify_trace_corpus`.
/// 4. Reports per-trace PASS/FAIL and exits non-zero on failure.
pub fn check_trace_oracle_current_workspace() -> Result<(), String> {
    check_trace_oracle_current_workspace_with_args(std::iter::empty())
}

pub fn check_trace_oracle_current_workspace_with_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(), String> {
    let repo_root = find_repo_root()?;
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--compare-trace" => {
                let trace = args
                    .next()
                    .ok_or_else(|| "--compare-trace requires a path".to_string())?;
                let requested_manifest_path = parse_manifest_path(&mut args)?;
                let trace_path = if PathBuf::from(&trace).is_absolute() {
                    PathBuf::from(trace)
                } else {
                    repo_root.join(trace)
                };
                let comparison = compare_model_and_runtime_trace(&trace_path)
                    .map_err(|e| format!("backend comparison failed: {e}"))?;
                let trace_path_label = trace_path_label(&repo_root, &trace_path);
                let trace_descriptor = trace_descriptor_from_label(&trace_path_label);
                let manifest = TraceArtifactManifest::local_comparison(
                    &comparison,
                    trace_path_label.clone(),
                    trace_descriptor.clone(),
                    generated_at_now_utc(),
                )
                .map_err(|e| format!("trace artifact manifest failed: {e}"))?;
                let manifest_path = requested_manifest_path.unwrap_or_else(|| {
                    default_manifest_path(
                        &repo_root,
                        &trace_descriptor,
                        TRACE_ARTIFACT_BACKEND_COMPARE,
                    )
                });
                manifest
                    .write_json_file(&manifest_path)
                    .map_err(|e| format!("write {}: {e}", manifest_path.display()))?;
                println!("trace: {}", trace_path.display());
                println!(
                    "model final fingerprint: {}",
                    comparison.final_fingerprint("model").unwrap_or("(none)")
                );
                println!(
                    "local-runtime final fingerprint: {}",
                    comparison
                        .final_fingerprint("local_runtime")
                        .unwrap_or("(none)")
                );
                println!("artifact manifest: {}", manifest_path.display());
                if let Some(first) = comparison.mismatches.first() {
                    return Err(first.to_string());
                }
                println!("model/local-runtime comparison: PASS");
                return Ok(());
            }
            "--trace" => {
                let trace_name = args
                    .next()
                    .ok_or_else(|| "--trace requires a trace name".to_string())?;
                let requested_manifest_path = parse_manifest_path(&mut args)?;
                return run_model_determinism_check(
                    &repo_root,
                    &trace_name,
                    requested_manifest_path,
                );
            }
            other => return Err(format!("unknown check-trace-oracle argument: {other}")),
        }
    }

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

/// Replay a named trace through the model backend twice and verify
/// deterministic output (same trace in, same fingerprint out across runs).
fn run_model_determinism_check(
    repo_root: &Path,
    trace_name: &str,
    requested_manifest_path: Option<PathBuf>,
) -> Result<(), String> {
    use tidefs_trace_oracle::backend::{run_trace_with_backend, ModelTraceBackend};

    // Look up the trace by name/id from MANIFEST.json.
    let manifest_path = repo_root.join("traces").join("MANIFEST.json");
    if !manifest_path.exists() {
        return Err(format!(
            "MANIFEST.json not found at {}",
            manifest_path.display()
        ));
    }
    let manifest =
        load_manifest(&manifest_path).map_err(|e| format!("failed to load manifest: {e}"))?;

    let item = manifest
        .items
        .iter()
        .find(|item| item.id == trace_name || item.path.contains(trace_name))
        .ok_or_else(|| {
            format!(
                "trace '{trace_name}' not found in manifest ({} entries)",
                manifest.items.len()
            )
        })?;

    let trace_path = if PathBuf::from(&item.path).is_absolute() {
        PathBuf::from(&item.path)
    } else {
        repo_root.join(&item.path)
    };

    if !trace_path.exists() {
        return Err(format!("trace file not found: {}", trace_path.display()));
    }

    // First replay.
    let mut backend_a = ModelTraceBackend::new();
    let events_a = run_trace_with_backend(&mut backend_a, &trace_path)
        .map_err(|e| format!("first model replay failed: {e}"))?;
    let fp_a = events_a
        .last()
        .and_then(|e| e.fingerprint.as_deref())
        .unwrap_or("(none)")
        .to_string();

    // Second replay (fresh backend).
    let mut backend_b = ModelTraceBackend::new();
    let events_b = run_trace_with_backend(&mut backend_b, &trace_path)
        .map_err(|e| format!("second model replay failed: {e}"))?;
    let fp_b = events_b
        .last()
        .and_then(|e| e.fingerprint.as_deref())
        .unwrap_or("(none)")
        .to_string();

    println!("trace: {}", trace_path.display());
    println!("trace name: {trace_name}");
    println!("operations replayed: {}", events_a.len());
    println!("run 1 fingerprint: {fp_a}");
    println!("run 2 fingerprint: {fp_b}");

    let result = if fp_a == fp_b {
        ArtifactRunResult::Pass
    } else {
        ArtifactRunResult::Fail
    };
    let trace_path_label = trace_path_label(repo_root, &trace_path);
    let manifest = TraceArtifactManifest::model_replay(
        &trace_path,
        trace_path_label,
        item.id.clone(),
        &events_a,
        result,
        generated_at_now_utc(),
    )
    .map_err(|e| format!("trace artifact manifest failed: {e}"))?;
    let manifest_path = requested_manifest_path
        .unwrap_or_else(|| default_manifest_path(repo_root, &item.id, BACKEND_MODEL));
    manifest
        .write_json_file(&manifest_path)
        .map_err(|e| format!("write {}: {e}", manifest_path.display()))?;
    println!("artifact manifest: {}", manifest_path.display());

    if result == ArtifactRunResult::Pass {
        println!("model determinism check: PASS");
        Ok(())
    } else {
        Err(format!(
            "model determinism check: FAIL (fingerprints differ: {fp_a} vs {fp_b})"
        ))
    }
}

fn parse_manifest_path(args: &mut impl Iterator<Item = String>) -> Result<Option<PathBuf>, String> {
    let mut manifest_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => {
                if manifest_path.is_some() {
                    return Err("duplicate check-trace-oracle --manifest argument".into());
                }
                let path = args
                    .next()
                    .ok_or_else(|| "--manifest requires a path".to_string())?;
                manifest_path = Some(PathBuf::from(path));
            }
            other => return Err(format!("unexpected check-trace-oracle argument: {other}")),
        }
    }
    Ok(manifest_path)
}

fn trace_path_label(repo_root: &Path, trace_path: &Path) -> String {
    trace_path
        .strip_prefix(repo_root)
        .unwrap_or(trace_path)
        .display()
        .to_string()
}

fn trace_descriptor_from_label(trace_path_label: &str) -> String {
    let without_jsonl = trace_path_label
        .strip_suffix(".jsonl")
        .unwrap_or(trace_path_label);
    sanitize_artifact_id(without_jsonl)
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
