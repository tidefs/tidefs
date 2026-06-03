//! Rust-native golden trace generation tests.
//!
//! Run with: cargo test -p tidefs-trace-oracle -- --ignored --nocapture
//!
//! Each scenario defines a sequence of deterministic pool ops, runs them
//! through a fresh TraceRunner to capture the state fingerprint, then
//! writes the full golden trace (including assert_fingerprint and
//! restart_pool lines) to `traces/golden/<scenario>/pool_trace.jsonl`.

use std::path::{Path, PathBuf};

use serde_json::json;
use tidefs_trace_oracle::{sha256_file, TraceError, TraceRunner};

/// Return the repo root (two levels up from the crate directory).
fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .expect("parent of crates/tidefs-trace-oracle")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

// ── Scenario definitions (no assert/restart -- those are added by the generator) ──

fn smoke_churn_ops() -> Vec<serde_json::Value> {
    vec![
        json!({"op":"trace_meta","args":{"schema":"pool_trace_v1","version":1}}),
        json!({"op":"create_pool","args":{"bootstrap_b64":"dmliZWZzLWJvb3RzdHJhcA==","device_count":2,"device_size_bytes":12582912}}),
        json!({"op":"create_dataset","args":{"name":"ds"}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k0.0","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k0.1","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k0.2","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k1.0","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k1.1","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k1.2","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k2.0","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k2.1","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
        json!({"op":"put","args":{"dataset":"ds","key":"k2.2","value_b64":"dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="}}),
    ]
}

/// Smoke storm: fewer puts than the Python original to avoid a known
/// content-chunk-accumulation bug in LocalFileSystem (tracked as
/// separate issue). Once fixed, the group counts can be increased.
fn smoke_storm_ops() -> Vec<serde_json::Value> {
    let mut ops = vec![
        json!({"op":"trace_meta","args":{"schema":"pool_trace_v1","version":1}}),
        json!({"op":"create_pool","args":{"bootstrap_b64":"dmliZWZzLWJvb3RzdHJhcA==","device_count":2,"device_size_bytes":12582912}}),
        json!({"op":"create_dataset","args":{"name":"ds"}}),
    ];
    // 3 groups of 8 puts = 24 total
    for group in 0..3 {
        for idx in 0..8 {
            let key = format!("s{group}.{idx}");
            ops.push(json!({
                "op": "put",
                "args": {
                    "dataset": "ds",
                    "key": key,
                    "value_b64": "dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnY="
                }
            }));
        }
    }
    ops
}

// ── Golden trace generation ────────────────────────────────────────────────

/// Run pure-data ops through a fresh TraceRunner, capture the fingerprint,
/// and produce the complete golden trace JSONL text.
fn generate_golden_trace(
    ops: &[serde_json::Value],
) -> Result<(String, String, String), TraceError> {
    let temp_dir = tempfile::tempdir()?;
    let temp_trace_path = temp_dir.path().join("bare.jsonl");

    // Phase 1: write bare ops (no assert/restart) and replay to get fingerprint.
    let mut bare_jsonl = String::new();
    for op in ops {
        bare_jsonl.push_str(&serde_json::to_string(op)?);
        bare_jsonl.push('\n');
    }
    std::fs::write(&temp_trace_path, &bare_jsonl)?;

    let mut runner = TraceRunner::new()?;
    let events = runner.run_trace(&temp_trace_path)?;
    let fingerprint = events
        .last()
        .and_then(|e| e.fingerprint.as_deref())
        .unwrap_or("")
        .to_string();

    // Phase 2: build full golden trace with assert + restart + assert.
    let mut full_jsonl = bare_jsonl;
    full_jsonl.push_str(&serde_json::to_string(&json!({
        "expect": {"fingerprint": &fingerprint},
        "op": "assert_fingerprint"
    }))?);
    full_jsonl.push('\n');
    full_jsonl.push_str(&serde_json::to_string(&json!({"op": "restart_pool"}))?);
    full_jsonl.push('\n');
    full_jsonl.push_str(&serde_json::to_string(&json!({
        "expect": {"fingerprint": &fingerprint},
        "op": "assert_fingerprint"
    }))?);
    full_jsonl.push('\n');

    // sha256 of the full golden trace.
    let final_path = temp_dir.path().join("golden.jsonl");
    std::fs::write(&final_path, &full_jsonl)?;
    let sha256 = sha256_file(&final_path)?;

    Ok((full_jsonl, sha256, fingerprint))
}

/// Helper: generate and write a single scenario's golden trace.
fn regenerate_scenario(name: &str, ops: &[serde_json::Value], golden_base: &Path) {
    let (content, sha256, fingerprint) =
        generate_golden_trace(ops).unwrap_or_else(|e| panic!("generate {name}: {e}"));

    let dir = golden_base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pool_trace.jsonl");
    std::fs::write(&path, &content).unwrap();

    println!("=== {name} ===");
    println!("  sha256:      {sha256}");
    println!("  fingerprint: {fingerprint}");
    println!("  written to:  {}", path.display());
}

// ── Individual test entry points ───────────────────────────────────────────

#[test]
#[ignore = "regenerate golden trace for smoke_churn"]
fn regenerate_smoke_churn() {
    let root = repo_root();
    let golden_base = root.join("traces").join("golden");
    regenerate_scenario("smoke_churn", &smoke_churn_ops(), &golden_base);
}

#[test]
#[ignore = "regenerate golden trace for smoke_storm"]
fn regenerate_smoke_storm() {
    let root = repo_root();
    let golden_base = root.join("traces").join("golden");
    regenerate_scenario("smoke_storm", &smoke_storm_ops(), &golden_base);
}
