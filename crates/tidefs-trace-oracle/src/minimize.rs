// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Trace minimizer: reduces failing traces to minimal reproducers.
//!
//! When a trace fails during replay, the minimizer applies three phases:
//!
//! **Phase 1:** Binary search for the shortest failing prefix.
//! **Phase 2:** Operation simplification (payload reduction, device size halving).
//! **Phase 3:** Redundant-op removal.
//!
//! The output is written as a minimal reproducer trace at
//! `traces/golden/minimized/<id>.jsonl`.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend::replay_command;
use crate::protocol::*;
use crate::{load_trace, save_trace, TraceError, TraceEvent};

/// Context required for trace replay during minimization.
pub struct MinimizerContext {
    /// The original failing trace id.
    pub trace_id: String,
    /// Path to the original trace file.
    pub trace_path: PathBuf,
    /// Output directory for minimized traces.
    pub output_dir: PathBuf,
}

/// Result of minimization.
#[derive(Debug)]
pub struct MinimizeResult {
    pub original_op_count: usize,
    pub minimized_op_count: usize,
    pub output_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_entry: MinimizedManifestEntry,
}

/// Sidecar manifest entry emitted with each minimized trace.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MinimizedManifestEntry {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub original_trace_path: String,
    pub original_op_count: usize,
    pub minimized_op_count: usize,
    pub replay_command: String,
}

/// Run full minimization (phases 1-3) on a failing trace.
///
/// The replay function `replay` takes a list of trace ops and returns
/// `Ok(events)` on success or `Err(...)` on failure. The minimizer uses
/// this to test whether a reduced trace still fails.
pub fn minimize_trace<F>(ctx: &MinimizerContext, replay: F) -> Result<MinimizeResult, TraceError>
where
    F: Fn(&[Value]) -> Result<Vec<TraceEvent>, TraceError>,
{
    let ops = load_trace(&ctx.trace_path)?;
    let trace_meta = ops.first().cloned();

    // Separate meta op from data ops.
    let data_ops: Vec<Value> = ops
        .into_iter()
        .skip_while(|v| {
            v.get(KEY_OP)
                .and_then(|o| o.as_str())
                .map(|o| o == OP_TRACE_META)
                .unwrap_or(false)
        })
        .collect();

    let original_count = data_ops.len();

    // Phase 1: binary search for minimal failing prefix.
    let mut current = phase1_binary_search(&data_ops, &replay)?;

    // Phase 2: operation simplification.
    current = phase2_simplify(current, &replay)?;

    // Phase 3: redundant-op removal.
    current = phase3_remove_redundant(current, &replay)?;

    // Reconstruct full trace with meta op.
    let mut output_ops: Vec<Value> = Vec::new();
    if let Some(meta) = trace_meta {
        output_ops.push(meta);
    }
    output_ops.extend(current);

    // Write minimized trace.
    fs::create_dir_all(&ctx.output_dir)?;
    let output_path = ctx.output_dir.join(format!("{}.jsonl", ctx.trace_id));
    save_trace(&output_path, &output_ops)?;
    let minimized_op_count = output_ops.len().saturating_sub(1);
    let manifest_entry = MinimizedManifestEntry {
        id: ctx.trace_id.clone(),
        kind: "minimized_trace_reproducer".into(),
        path: output_path.display().to_string(),
        original_trace_path: ctx.trace_path.display().to_string(),
        original_op_count: original_count,
        minimized_op_count,
        replay_command: replay_command(&output_path),
    };
    let manifest_path = ctx
        .output_dir
        .join(format!("{}.manifest.json", ctx.trace_id));
    let manifest_json = serde_json::to_string_pretty(&manifest_entry)?;
    fs::write(&manifest_path, format!("{manifest_json}\n"))?;

    Ok(MinimizeResult {
        original_op_count: original_count,
        minimized_op_count,
        output_path,
        manifest_path,
        manifest_entry,
    })
}

// ── Phase 1: binary search for minimal failing prefix ──────────────────────

fn phase1_binary_search<F>(ops: &[Value], replay: &F) -> Result<Vec<Value>, TraceError>
where
    F: Fn(&[Value]) -> Result<Vec<TraceEvent>, TraceError>,
{
    let n = ops.len();
    let mut lo: usize = 1;
    let mut hi: usize = n;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let prefix = &ops[..mid];
        match replay(prefix) {
            Ok(_) => lo = mid + 1, // Prefix passes; need more ops.
            Err(_) => hi = mid,    // Prefix fails; can shrink.
        }
    }

    Ok(ops[..lo].to_vec())
}

// ── Phase 2: operation simplification ──────────────────────────────────────

fn phase2_simplify<F>(ops: Vec<Value>, replay: &F) -> Result<Vec<Value>, TraceError>
where
    F: Fn(&[Value]) -> Result<Vec<TraceEvent>, TraceError>,
{
    let mut current = ops;

    for i in 0..current.len() {
        let op_name = current[i]
            .get(KEY_OP)
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match op_name {
            OP_PUT | OP_WRITE_RANGE => {
                // Try reducing payload size.
                if let Some(reduced) = simplify_payload(&current[i]) {
                    let mut candidate = current.clone();
                    candidate[i] = reduced;
                    if replay(&candidate).is_err() {
                        // Still fails; keep reduced version.
                        current = candidate;
                    }
                }
            }
            OP_CREATE_POOL => {
                // Try halving device size.
                if let Some(reduced) = simplify_device_size(&current[i]) {
                    let mut candidate = current.clone();
                    candidate[i] = reduced;
                    if replay(&candidate).is_err() {
                        current = candidate;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(current)
}

/// Reduce payload for put/write_range to a 4-byte value.
fn simplify_payload(op: &Value) -> Option<Value> {
    let value_b64 = op
        .get(KEY_ARGS)
        .and_then(|a| a.get(KEY_VALUE_B64))
        .or_else(|| op.get(KEY_ARGS).and_then(|a| a.get(KEY_DATA_B64)))
        .and_then(|v| v.as_str())?;

    // Decode current payload; if > 4 bytes, replace with 4-byte payload.
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(value_b64)
        .ok()?;

    if data.len() <= 4 {
        return None; // Already minimal.
    }

    let reduced = base64::engine::general_purpose::STANDARD.encode(b"\x00\x00\x00\x00");

    let mut new_op = op.clone();
    if let Some(args) = new_op.get_mut(KEY_ARGS) {
        if let Some(obj) = args.as_object_mut() {
            if obj.contains_key(KEY_VALUE_B64) {
                obj.insert(KEY_VALUE_B64.to_string(), Value::String(reduced.clone()));
            }
            if obj.contains_key(KEY_DATA_B64) {
                obj.insert(KEY_DATA_B64.to_string(), Value::String(reduced.clone()));
            }
        }
    }

    Some(new_op)
}

/// Halve device_size_bytes for create_pool.
fn simplify_device_size(op: &Value) -> Option<Value> {
    let size = op
        .get(KEY_ARGS)
        .and_then(|a| a.get(KEY_DEVICE_SIZE_BYTES))
        .and_then(|v| v.as_u64())?;

    // Minimum viable device size: 1 MiB.
    const MIN_SIZE: u64 = 1024 * 1024;

    if size <= MIN_SIZE {
        return None;
    }

    let halved = std::cmp::max(size / 2, MIN_SIZE);

    let mut new_op = op.clone();
    if let Some(args) = new_op.get_mut(KEY_ARGS) {
        if let Some(obj) = args.as_object_mut() {
            obj.insert(
                KEY_DEVICE_SIZE_BYTES.to_string(),
                Value::Number(halved.into()),
            );
        }
    }

    Some(new_op)
}

// ── Phase 3: redundant-op removal ──────────────────────────────────────────

fn phase3_remove_redundant<F>(ops: Vec<Value>, replay: &F) -> Result<Vec<Value>, TraceError>
where
    F: Fn(&[Value]) -> Result<Vec<TraceEvent>, TraceError>,
{
    let mut current = ops;
    let mut i: isize = 0;

    while (i as usize) < current.len() {
        let idx = i as usize;

        // Skip meta-like ops that shouldn't be removed.
        let op_name = current[idx]
            .get(KEY_OP)
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if matches!(
            op_name,
            OP_TRACE_META | OP_CREATE_POOL | OP_OPEN_POOL | OP_CLOSE_POOL | OP_ASSERT_FINGERPRINT
        ) {
            i += 1;
            continue;
        }

        // Try removing this op.
        let candidate: Vec<Value> = current
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != idx)
            .map(|(_, v)| v.clone())
            .collect();

        if replay(&candidate).is_err() {
            // Still fails; keep reduced version and re-check this index.
            current = candidate;
            // Don't increment i - re-examine the op that shifted into this position.
        } else {
            i += 1;
        }
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    // ── simplify_payload tests ──────────────────────────────────────────

    #[test]
    fn simplify_payload_reduces_large_value() {
        // 16-byte payload through value_b64 path (put op)
        let data = b"hello world test!";
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let op = json!({
            "op": "put",
            "args": { "value_b64": b64 }
        });
        let reduced = simplify_payload(&op);
        assert!(reduced.is_some());
        let new_b64 = reduced.unwrap()["args"]["value_b64"]
            .as_str()
            .unwrap()
            .to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&new_b64)
            .unwrap();
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn simplify_payload_reduces_large_data() {
        // 32-byte payload through data_b64 path (write_range op)
        let data = b"some binary content for write_range";
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let op = json!({
            "op": "write_range",
            "args": { "data_b64": b64 }
        });
        let reduced = simplify_payload(&op);
        assert!(reduced.is_some());
        let new_b64 = reduced.unwrap()["args"]["data_b64"]
            .as_str()
            .unwrap()
            .to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&new_b64)
            .unwrap();
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn simplify_payload_already_minimal_4_bytes() {
        let data = b"\x01\x02\x03\x04";
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let op = json!({
            "op": "put",
            "args": { "value_b64": b64 }
        });
        assert!(simplify_payload(&op).is_none());
    }

    #[test]
    fn simplify_payload_already_minimal_under_4_bytes() {
        let data = b"ab";
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let op = json!({
            "op": "put",
            "args": { "value_b64": b64 }
        });
        assert!(simplify_payload(&op).is_none());
    }

    #[test]
    fn simplify_payload_missing_args() {
        let op = json!({"op": "put"});
        assert!(simplify_payload(&op).is_none());
    }

    #[test]
    fn simplify_payload_missing_value_key() {
        let op = json!({
            "op": "put",
            "args": { "other": "data" }
        });
        assert!(simplify_payload(&op).is_none());
    }

    #[test]
    fn simplify_payload_invalid_base64() {
        let op = json!({
            "op": "put",
            "args": { "value_b64": "!!!not-base64!!!" }
        });
        assert!(simplify_payload(&op).is_none());
    }

    // ── simplify_device_size tests ──────────────────────────────────────

    #[test]
    fn simplify_device_size_halves_large_device() {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let op = json!({
            "op": "create_pool",
            "args": { "device_size_bytes": TWO_MIB }
        });
        let reduced = simplify_device_size(&op);
        assert!(reduced.is_some());
        let new_size = reduced.unwrap()["args"]["device_size_bytes"]
            .as_u64()
            .unwrap();
        assert_eq!(new_size, 1024 * 1024);
    }

    #[test]
    fn simplify_device_size_at_min_returns_none() {
        const ONE_MIB: u64 = 1024 * 1024;
        let op = json!({
            "op": "create_pool",
            "args": { "device_size_bytes": ONE_MIB }
        });
        assert!(simplify_device_size(&op).is_none());
    }

    #[test]
    fn simplify_device_size_below_min_returns_none() {
        let op = json!({
            "op": "create_pool",
            "args": { "device_size_bytes": 512 }
        });
        assert!(simplify_device_size(&op).is_none());
    }

    #[test]
    fn simplify_device_size_just_above_min() {
        // 1 MiB + 1 byte → halved but clamped to MIN_SIZE
        const SIZE: u64 = 1024 * 1024 + 1;
        let op = json!({
            "op": "create_pool",
            "args": { "device_size_bytes": SIZE }
        });
        let reduced = simplify_device_size(&op);
        assert!(reduced.is_some());
        let new_size = reduced.unwrap()["args"]["device_size_bytes"]
            .as_u64()
            .unwrap();
        assert_eq!(new_size, 1024 * 1024); // clamped to MIN_SIZE
    }

    #[test]
    fn simplify_device_size_missing_args() {
        let op = json!({"op": "create_pool"});
        assert!(simplify_device_size(&op).is_none());
    }

    #[test]
    fn simplify_device_size_missing_size_key() {
        let op = json!({
            "op": "create_pool",
            "args": { "other": 42 }
        });
        assert!(simplify_device_size(&op).is_none());
    }

    #[test]
    fn simplify_device_size_non_u64_value() {
        let op = json!({
            "op": "create_pool",
            "args": { "device_size_bytes": "not-a-number" }
        });
        assert!(simplify_device_size(&op).is_none());
    }

    #[test]
    fn minimize_writes_reproducer_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let trace_path = temp.path().join("failing.jsonl");
        save_trace(
            &trace_path,
            &[
                json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
                json!({"op": "create_pool", "args": {"device_size_bytes": 2097152}}),
                json!({"op": "put", "args": {"value_b64": "YWJjZGVm"}}),
            ],
        )
        .unwrap();
        let ctx = MinimizerContext {
            trace_id: "mini".into(),
            trace_path,
            output_dir: temp.path().join("out"),
        };
        let result = minimize_trace(&ctx, |ops| {
            if ops.is_empty() {
                Ok(Vec::new())
            } else {
                Err(TraceError::Assertion("still failing".into()))
            }
        })
        .unwrap();

        assert!(result.output_path.exists());
        assert!(result.manifest_path.exists());
        assert_eq!(result.manifest_entry.original_op_count, 2);
        assert!(result
            .manifest_entry
            .replay_command
            .contains("check-trace-oracle --compare-trace"));
    }
}
