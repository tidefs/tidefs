//! Trace I/O roundtrip tests.
//!
//! Verifies that trace files can be written and read back with identical
//! content through the deterministic JSONL serialiser.

use serde_json::json;
use tempfile::TempDir;

use tidefs_trace_oracle::backend::compare_model_and_runtime_trace;
use tidefs_trace_oracle::protocol::{OP_FSYNC, POOL_TRACE_OPS};
use tidefs_trace_oracle::{load_trace, save_trace, JsonlTraceWriter};

#[test]
fn test_write_read_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("roundtrip.jsonl");

    let ops = vec![
        json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
        json!({"op": "create_pool", "args": {"device_count": 1, "device_size_bytes": 4194304}}),
        json!({"op": "create_dataset", "args": {"name": "test"}}),
    ];

    save_trace(&path, &ops).unwrap();
    let loaded = load_trace(&path).unwrap();

    assert_eq!(loaded.len(), ops.len());
    for (i, (expected, actual)) in ops.iter().zip(loaded.iter()).enumerate() {
        assert_eq!(expected, actual, "mismatch at index {i}");
    }
}

#[test]
fn test_jsonl_writer_streaming() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("stream.jsonl");

    let mut writer = JsonlTraceWriter::new(&path).unwrap();
    writer
        .write_op(&json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}))
        .unwrap();
    writer
        .write_op(&json!({"op": "create_pool", "args": {"device_count": 2, "device_size_bytes": 33554432}}))
        .unwrap();
    writer.close().unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("trace_meta"));
    assert!(lines[1].contains("create_pool"));
}

#[test]
fn model_runtime_backend_smoke_trace_matches() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let trace_path = root
        .join("traces")
        .join("golden")
        .join("model_runtime_smoke")
        .join("pool_trace.jsonl");

    let comparison = compare_model_and_runtime_trace(&trace_path).unwrap();

    assert!(comparison.passed());
    assert_eq!(
        comparison.final_fingerprint("model"),
        Some("57472c0e915ed47da807476b61edf1e5f91fc96076423ac5412b8e63ce04eb49")
    );
    assert_eq!(
        comparison.final_fingerprint("local_runtime"),
        Some("1b5ff6cab46a09b38b0270d739ed5abdcbf17cb631219ad729439cd9230d3222")
    );
}

#[test]
fn model_runtime_write_sync_restart_trace_matches() {
    assert!(POOL_TRACE_OPS.contains(&OP_FSYNC));

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let trace_path = root
        .join("traces")
        .join("local-vfs-write-fsync-read-recovery.jsonl");

    let comparison = compare_model_and_runtime_trace(&trace_path).unwrap();

    assert!(comparison.passed(), "{:#?}", comparison.mismatches);
    assert!(comparison.final_fingerprint("model").is_some());
    assert!(comparison.final_fingerprint("local_runtime").is_some());
}

#[test]
fn model_runtime_rename_sync_restart_trace_passes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let trace_path = root
        .join("traces")
        .join("local-vfs-rename-atomicity-read-recovery.jsonl");
    let comparison = compare_model_and_runtime_trace(&trace_path).unwrap();

    assert!(
        comparison.passed(),
        "rename atomicity trace mismatch: {:?}",
        comparison.mismatches.first().map(|m| m.to_string())
    );
    assert!(
        comparison.final_fingerprint("model").is_some(),
        "rename trace missing model final fingerprint"
    );
    assert!(
        comparison.final_fingerprint("local_runtime").is_some(),
        "rename trace missing runtime final fingerprint"
    );
}

#[test]
fn backend_mismatch_reports_replay_metadata() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("mismatch.jsonl");
    save_trace(
        &path,
        &[
            json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
            json!({"op": "create_pool", "args": {"device_count": 1, "device_size_bytes": 4194304}}),
            json!({"op": "create_dataset", "args": {"name": "ds"}}),
            json!({"op": "create_file", "args": {"dataset": "ds", "path": "source"}}),
            json!({"op": "write_range", "args": {"dataset": "ds", "key": "source", "offset": 0, "data_b64": "YWJjZA=="}}),
            json!({"op": "create_snapshot", "args": {"name": "snap"}}),
        ],
    )
    .unwrap();

    let comparison = compare_model_and_runtime_trace(&path).unwrap();

    assert!(!comparison.passed());
    let mismatch = comparison.mismatches.first().unwrap();
    assert_eq!(mismatch.operation_index, 5);
    assert_eq!(mismatch.request.op, "create_snapshot");
    assert_eq!(mismatch.model_completion.status, "unsupported");
    assert_eq!(mismatch.runtime_completion.status, "success");
    assert!(mismatch.fingerprint_delta.model.is_some());
    assert!(mismatch.fingerprint_delta.runtime.is_some());
    assert!(mismatch
        .replay_command
        .contains("check-trace-oracle --compare-trace"));

    let rendered = mismatch.to_string();
    assert!(rendered.contains("operation 5"));
    assert!(rendered.contains("model completion"));
    assert!(rendered.contains("runtime completion"));
    assert!(rendered.contains("fingerprint delta"));
    assert!(rendered.contains("replay:"));
}

#[test]
fn backend_runner_rejects_future_trace_version() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("future.jsonl");
    save_trace(
        &path,
        &[json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 99}})],
    )
    .unwrap();

    let err = compare_model_and_runtime_trace(&path).unwrap_err();
    assert!(err.to_string().contains("unsupported version: 99"));
}
