//! Trace oracle: deterministic operation recording and replay for peer crates.
//!
//! The `TraceEvent` enum covers the union of operations exposed by active peer
//! implementation crates.  Each variant carries typed payloads.  The whole
//! trace is serializable via `serde` so trace files can be written to disk and
//! replayed through a fresh harness for deterministic verification.
//!
//! New operations should be added here before they are wired into smoke modules.

use serde::{Deserialize, Serialize};

/// Validation command outcome in the validation trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ValidationStepStatus {
    Passed,
    Failed,
    Skipped,
}

/// Every operation the validation harness can record or replay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TraceEvent {
    // ── dir-index ──────────────────────────────────────────────────────────
    /// `DirIndex::insert`
    DirInsert {
        name: Vec<u8>,
        inode_id: u64,
        generation: u64,
        kind: u32,
    },
    /// `DirIndex::lookup`
    DirLookup { name: Vec<u8> },
    /// `DirIndex::delete`
    DirRemove { name: Vec<u8> },
    /// `DirIndex::list_from`
    DirIter { cookie: u64 },
    /// `DirIndex::replace`
    DirReplace {
        name: Vec<u8>,
        inode_id: u64,
        generation: u64,
        kind: u32,
    },
    /// `DirIndex::contains`
    DirContains { name: Vec<u8> },

    // ── inode-table (future) ───────────────────────────────────────────────
    /// Create an inode entry.
    InodeCreate {
        inode_id: u64,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    /// Get attributes.
    InodeGetattr { inode_id: u64 },
    /// Set attributes.
    InodeSetattr { inode_id: u64, attr_mask: u64 },
    /// Increment link count.
    InodeLink { inode_id: u64 },
    /// Decrement link count / remove.
    InodeUnlink { inode_id: u64 },

    // ── object-store ───────────────────────────────────────────────────────
    /// `LocalObjectStore::put` or equivalent.
    ObjectPut { key_bytes: Vec<u8>, value: Vec<u8> },
    /// `LocalObjectStore::get` or equivalent.
    ObjectGet { key_bytes: Vec<u8> },
    /// `LocalObjectStore::delete` or equivalent.
    ObjectDelete { key_bytes: Vec<u8> },
    /// Scan a range of objects.
    ObjectScan {
        start_key: Option<Vec<u8>>,
        limit: usize,
    },

    // ── extent-map ─────────────────────────────────────────────────────────
    /// Insert an extent entry.
    ExtentInsert {
        logical_offset: u64,
        length: u64,
        locator_id: u64,
        flags: u32,
    },
    /// Lookup extent for a byte range.
    ExtentLookup { offset: u64, length: u64 },
    /// Truncate file to a new size.
    ExtentTruncate { new_size: u64 },

    // ── namespace (future) ─────────────────────────────────────────────────
    /// Resolve a path to an inode.
    NamespaceResolve { path: Vec<u8> },
    /// Create a new directory entry.
    NamespaceCreate {
        parent: u64,
        name: Vec<u8>,
        mode: u32,
    },
    /// Unlink a name.
    NamespaceUnlink { parent: u64, name: Vec<u8> },

    // ── local-filesystem ───────────────────────────────────────────────────
    /// Open a filesystem at a given path.
    FsOpen { root_path: String },
    /// Trigger a lifecycle operation (create, read, write, etc.).
    FsLifecycleOp {
        inode_id: u64,
        op_name: String,
        payload: Vec<u8>,
    },
    /// Close the filesystem.
    FsClose,

    // ── harness meta ───────────────────────────────────────────────────────
    /// Marker: start a named scenario group (for readability).
    ScenarioBegin { name: String },
    /// Marker: end a named scenario group.
    ScenarioEnd { name: String },
    /// Assertion that was checked at replay time.
    Assert { condition: String, passed: bool },
    /// Validation command status captured for validation output.
    ValidationStep {
        name: String,
        command: String,
        status: ValidationStepStatus,
        exit_code: Option<i32>,
    },
}

// ── helpers ────────────────────────────────────────────────────────────────

impl TraceEvent {
    /// Short human-readable label for this variant (useful in logs).
    pub fn label(&self) -> &'static str {
        match self {
            TraceEvent::DirInsert { .. } => "DirInsert",
            TraceEvent::DirLookup { .. } => "DirLookup",
            TraceEvent::DirRemove { .. } => "DirRemove",
            TraceEvent::DirIter { .. } => "DirIter",
            TraceEvent::DirReplace { .. } => "DirReplace",
            TraceEvent::DirContains { .. } => "DirContains",
            TraceEvent::InodeCreate { .. } => "InodeCreate",
            TraceEvent::InodeGetattr { .. } => "InodeGetattr",
            TraceEvent::InodeSetattr { .. } => "InodeSetattr",
            TraceEvent::InodeLink { .. } => "InodeLink",
            TraceEvent::InodeUnlink { .. } => "InodeUnlink",
            TraceEvent::ObjectPut { .. } => "ObjectPut",
            TraceEvent::ObjectGet { .. } => "ObjectGet",
            TraceEvent::ObjectDelete { .. } => "ObjectDelete",
            TraceEvent::ObjectScan { .. } => "ObjectScan",
            TraceEvent::ExtentInsert { .. } => "ExtentInsert",
            TraceEvent::ExtentLookup { .. } => "ExtentLookup",
            TraceEvent::ExtentTruncate { .. } => "ExtentTruncate",
            TraceEvent::NamespaceResolve { .. } => "NamespaceResolve",
            TraceEvent::NamespaceCreate { .. } => "NamespaceCreate",
            TraceEvent::NamespaceUnlink { .. } => "NamespaceUnlink",
            TraceEvent::FsOpen { .. } => "FsOpen",
            TraceEvent::FsLifecycleOp { .. } => "FsLifecycleOp",
            TraceEvent::FsClose => "FsClose",
            TraceEvent::ScenarioBegin { .. } => "ScenarioBegin",
            TraceEvent::ScenarioEnd { .. } => "ScenarioEnd",
            TraceEvent::Assert { .. } => "Assert",
            TraceEvent::ValidationStep { .. } => "ValidationStep",
        }
    }
}

/// A complete operation trace: ordered list of recorded events.
pub type Trace = Vec<TraceEvent>;

/// Serialize a trace to a JSON byte vector suitable for writing to disk.
pub fn serialize_trace(trace: &Trace) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(trace)
}

/// Deserialize a trace from JSON bytes.
pub fn deserialize_trace(data: &[u8]) -> Result<Trace, serde_json::Error> {
    serde_json::from_slice(data)
}

/// Write a trace to a file on disk.
pub fn write_trace_to_file(
    trace: &Trace,
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = serialize_trace(trace)?;
    std::fs::write(path, data)?;
    Ok(())
}

/// Read a trace from a file on disk.
pub fn read_trace_from_file(path: &std::path::Path) -> Result<Trace, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let trace = deserialize_trace(&data)?;
    Ok(trace)
}

/// Replay a trace and verify all assertions passed.
///
/// Returns the list of assertion conditions that failed (if any).
pub fn verify_trace_assertions(trace: &Trace) -> Vec<String> {
    let mut failures = Vec::new();
    for event in trace {
        if let TraceEvent::Assert { condition, passed } = event {
            if !*passed {
                failures.push(condition.clone());
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_trace() {
        let trace: Trace = vec![];
        let data = serialize_trace(&trace).unwrap();
        let back = deserialize_trace(&data).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn round_trip_full_variants() {
        let trace: Trace = vec![
            TraceEvent::ScenarioBegin {
                name: "smoke".into(),
            },
            TraceEvent::DirInsert {
                name: b"hello".to_vec(),
                inode_id: 1,
                generation: 1,
                kind: 0o040755,
            },
            TraceEvent::DirLookup {
                name: b"hello".to_vec(),
            },
            TraceEvent::DirRemove {
                name: b"hello".to_vec(),
            },
            TraceEvent::DirIter { cookie: 0 },
            TraceEvent::DirReplace {
                name: b"foo".to_vec(),
                inode_id: 2,
                generation: 2,
                kind: 0o100644,
            },
            TraceEvent::DirContains {
                name: b"hello".to_vec(),
            },
            TraceEvent::InodeCreate {
                inode_id: 1,
                mode: 0o755,
                uid: 1000,
                gid: 1000,
            },
            TraceEvent::InodeGetattr { inode_id: 1 },
            TraceEvent::InodeSetattr {
                inode_id: 1,
                attr_mask: 0,
            },
            TraceEvent::InodeLink { inode_id: 1 },
            TraceEvent::InodeUnlink { inode_id: 1 },
            TraceEvent::ObjectPut {
                key_bytes: b"obj1".to_vec(),
                value: b"hello world".to_vec(),
            },
            TraceEvent::ObjectGet {
                key_bytes: b"obj1".to_vec(),
            },
            TraceEvent::ObjectDelete {
                key_bytes: b"obj1".to_vec(),
            },
            TraceEvent::ObjectScan {
                start_key: None,
                limit: 10,
            },
            TraceEvent::ExtentInsert {
                logical_offset: 0,
                length: 4096,
                locator_id: 1,
                flags: 0,
            },
            TraceEvent::ExtentLookup {
                offset: 0,
                length: 4096,
            },
            TraceEvent::ExtentTruncate { new_size: 0 },
            TraceEvent::NamespaceResolve {
                path: b"/foo".to_vec(),
            },
            TraceEvent::NamespaceCreate {
                parent: 1,
                name: b"bar".to_vec(),
                mode: 0o755,
            },
            TraceEvent::NamespaceUnlink {
                parent: 1,
                name: b"bar".to_vec(),
            },
            TraceEvent::FsOpen {
                root_path: "/tmp/test".into(),
            },
            TraceEvent::FsLifecycleOp {
                inode_id: 1,
                op_name: "write".into(),
                payload: b"data".to_vec(),
            },
            TraceEvent::FsClose,
            TraceEvent::Assert {
                condition: "1 == 1".into(),
                passed: true,
            },
            TraceEvent::ValidationStep {
                name: "compile gate".into(),
                command: "cargo check -p tidefs-validation".into(),
                status: ValidationStepStatus::Passed,
                exit_code: Some(0),
            },
            TraceEvent::ScenarioEnd {
                name: "smoke".into(),
            },
        ];

        let data = serialize_trace(&trace).unwrap();
        let back = deserialize_trace(&data).unwrap();
        assert_eq!(trace, back);
    }

    #[test]
    fn label_is_stable() {
        assert_eq!(
            TraceEvent::DirInsert {
                name: vec![],
                inode_id: 0,
                generation: 0,
                kind: 0
            }
            .label(),
            "DirInsert"
        );
        assert_eq!(TraceEvent::FsClose.label(), "FsClose");
        assert_eq!(
            TraceEvent::ValidationStep {
                name: "gate".into(),
                command: "false".into(),
                status: ValidationStepStatus::Failed,
                exit_code: Some(1),
            }
            .label(),
            "ValidationStep"
        );
    }

    #[test]
    fn file_round_trip_preserves_assertions() {
        let dir = std::env::temp_dir();
        let path = dir.join("tidefs_validation_trace_test.json");

        let trace: Trace = vec![
            TraceEvent::ScenarioBegin {
                name: "test".into(),
            },
            TraceEvent::DirInsert {
                name: b"k".to_vec(),
                inode_id: 1,
                generation: 0,
                kind: 0,
            },
            TraceEvent::DirLookup {
                name: b"k".to_vec(),
            },
            TraceEvent::Assert {
                condition: "found".into(),
                passed: true,
            },
            TraceEvent::ScenarioEnd {
                name: "test".into(),
            },
        ];

        write_trace_to_file(&trace, &path).expect("write trace to file");
        let back = read_trace_from_file(&path).expect("read trace from file");

        assert_eq!(trace, back);

        let failures = verify_trace_assertions(&back);
        assert!(
            failures.is_empty(),
            "unexpected assertion failures: {failures:?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_trace_detects_failure() {
        let trace: Trace = vec![
            TraceEvent::Assert {
                condition: "ok".into(),
                passed: true,
            },
            TraceEvent::Assert {
                condition: "bad".into(),
                passed: false,
            },
        ];
        let failures = verify_trace_assertions(&trace);
        assert_eq!(failures, vec!["bad".to_string()]);
    }

    #[test]
    fn validation_step_round_trip_preserves_failed_status() {
        let trace = vec![TraceEvent::ValidationStep {
            name: "fixture regression".into(),
            command: "cargo test -p tidefs-validation --test fixture_regression".into(),
            status: ValidationStepStatus::Failed,
            exit_code: Some(101),
        }];

        let data = serialize_trace(&trace).unwrap();
        let back = deserialize_trace(&data).unwrap();

        assert_eq!(trace, back);
    }
}
