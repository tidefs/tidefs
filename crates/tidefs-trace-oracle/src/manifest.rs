//! Golden trace corpus manifest loader and verifier.
//!
//! Loads `traces/MANIFEST.json`, verifies sha256 of trace files, and replays
//! pool traces through `TraceRunner` to compare final fingerprints.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{sha256_file, TraceError, TraceEvent, TraceRunner};

/// Top-level manifest structure.
#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub manifest_version: u64,
    #[serde(default)]
    pub generated_by: String,
    pub items: Vec<ManifestItem>,
}

/// A single entry in the trace corpus.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ManifestItem {
    pub id: String,
    pub description: String,
    pub kind: String,
    pub path: String,
    pub schema: String,
    pub sha256: String,
    pub expected_fingerprint: String,
}

/// Result of replaying one trace from the manifest.
#[derive(Debug)]
pub struct TraceResult {
    pub id: String,
    pub passed: bool,
    pub events: Option<Vec<TraceEvent>>,
    pub error: Option<String>,
    pub sha256_ok: bool,
}

/// Load a manifest from disk.
pub fn load_manifest(path: &Path) -> Result<Manifest, TraceError> {
    let data = std::fs::read_to_string(path)?;
    let manifest: Manifest = serde_json::from_str(&data)?;
    Ok(manifest)
}

/// Verify the entire trace corpus described by the manifest.
///
/// For each pool trace entry:
/// 1. Verifies sha256 of the trace file matches the manifest.
/// 2. Replays the trace through a fresh `TraceRunner`.
/// 3. Compares the final event fingerprint against the manifest expectation.
///
/// Returns per-entry results. Cluster traces (kind != "pool") are skipped.
pub fn verify_trace_corpus(
    repo_root: &Path,
    manifest: &Manifest,
) -> Result<Vec<TraceResult>, TraceError> {
    let mut results: Vec<TraceResult> = Vec::new();

    for item in &manifest.items {
        // Only pool traces are currently in scope.
        if item.kind != "pool" {
            results.push(TraceResult {
                id: item.id.clone(),
                passed: true, // Skipped cluster traces are not failures.
                events: None,
                error: Some("skipped (cluster traces deferred)".into()),
                sha256_ok: true,
            });
            continue;
        }

        let trace_path = repo_root.join(&item.path);

        // 1. Verify sha256.
        let sha256_ok = match sha256_file(&trace_path) {
            Ok(hash) => hash == item.sha256,
            Err(e) => {
                results.push(TraceResult {
                    id: item.id.clone(),
                    passed: false,
                    events: None,
                    error: Some(format!("sha256 error: {e}")),
                    sha256_ok: false,
                });
                continue;
            }
        };

        if !sha256_ok {
            results.push(TraceResult {
                id: item.id.clone(),
                passed: false,
                events: None,
                error: Some("sha256 mismatch".into()),
                sha256_ok: false,
            });
            continue;
        }

        // 2. Replay trace.
        let mut runner = TraceRunner::new()?;
        match runner.run_trace(&trace_path) {
            Ok(events) => {
                // 3. Compare final fingerprint.
                let last_fp = events
                    .last()
                    .and_then(|e| e.fingerprint.as_deref())
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                let passed = last_fp == item.expected_fingerprint;
                let err_msg = if !passed {
                    Some(format!(
                        "fingerprint mismatch: expected {}, got {}",
                        item.expected_fingerprint,
                        if last_fp.is_empty() {
                            "(none)"
                        } else {
                            &last_fp
                        }
                    ))
                } else {
                    None
                };

                results.push(TraceResult {
                    id: item.id.clone(),
                    passed,
                    events: Some(events),
                    error: err_msg,
                    sha256_ok,
                });
            }
            Err(e) => {
                results.push(TraceResult {
                    id: item.id.clone(),
                    passed: false,
                    events: None,
                    error: Some(format!("replay error: {e}")),
                    sha256_ok,
                });
            }
        }
    }

    Ok(results)
}

/// Print human-readable results from `verify_trace_corpus`.
pub fn print_results(results: &[TraceResult]) {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for r in results {
        match (r.passed, &r.error) {
            (true, None) => {
                println!("PASS  {}", r.id);
                passed += 1;
            }
            (true, Some(msg)) if msg.starts_with("skipped") => {
                println!("SKIP  {}  ({msg})", r.id);
                skipped += 1;
            }
            (false, Some(msg)) => {
                println!("FAIL  {}  {msg}", r.id);
                failed += 1;
            }
            _ => {
                println!("???   {}", r.id);
            }
        }
    }

    println!();
    println!("Results: {passed} passed, {failed} failed, {skipped} skipped");
}
