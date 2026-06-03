//! Trace I/O roundtrip tests.
//!
//! Verifies that trace files can be written and read back with identical
//! content through the deterministic JSONL serialiser.

use serde_json::json;
use tempfile::TempDir;

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
