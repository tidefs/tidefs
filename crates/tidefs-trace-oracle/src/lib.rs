// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic trace oracle for cross-implementation semantic regression testing.
//!
//! Replays JSONL trace files against `LocalFileSystem`, tracking per-step cost
//! deltas and computing deterministic BLAKE3-256 state fingerprints.

pub mod backend;
pub mod manifest;
pub mod minimize;
pub mod protocol;

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use tidefs_local_filesystem::{FileSystemStats, LocalFileSystem, NamespaceEntry};
use tidefs_types_vfs_core::NodeKind;

use protocol::*;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TraceError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    FileSystem(String),
    Protocol(String),
    Assertion(String),
    Minimize(String),
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Base64(e) => write!(f, "base64 error: {e}"),
            Self::FileSystem(s) => write!(f, "filesystem error: {s}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
            Self::Assertion(s) => write!(f, "assertion failed: {s}"),
            Self::Minimize(s) => write!(f, "minimize error: {s}"),
        }
    }
}

impl std::error::Error for TraceError {}

impl From<std::io::Error> for TraceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for TraceError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<base64::DecodeError> for TraceError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e)
    }
}

// ── Cost baseline ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CostBaseline {
    pub read_ops: u64,
    pub write_ops: u64,
    pub flush_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl CostBaseline {
    pub fn delta(after: &Self, before: &Self) -> Self {
        Self {
            read_ops: after.read_ops.saturating_sub(before.read_ops),
            write_ops: after.write_ops.saturating_sub(before.write_ops),
            flush_ops: after.flush_ops.saturating_sub(before.flush_ops),
            read_bytes: after.read_bytes.saturating_sub(before.read_bytes),
            write_bytes: after.write_bytes.saturating_sub(before.write_bytes),
        }
    }

    pub fn accumulate(&mut self, other: &Self) {
        self.read_ops = self.read_ops.saturating_add(other.read_ops);
        self.write_ops = self.write_ops.saturating_add(other.write_ops);
        self.flush_ops = self.flush_ops.saturating_add(other.flush_ops);
        self.read_bytes = self.read_bytes.saturating_add(other.read_bytes);
        self.write_bytes = self.write_bytes.saturating_add(other.write_bytes);
    }

    fn from_fs_stats(stats: &FileSystemStats) -> Self {
        let total_objects = (stats.inode_count + stats.snapshot_count) as u64;
        Self {
            read_ops: 0,
            write_ops: total_objects,
            flush_ops: 0,
            read_bytes: 0,
            write_bytes: stats.inode_count.saturating_mul(512) as u64,
        }
    }
}

// ── Trace event ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEvent {
    pub step: u64,
    pub op: String,
    pub cost: CostBaseline,
    pub fingerprint: Option<String>,
    pub result: Option<serde_json::Value>,
}

// ── Raw trace line ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TraceLine {
    op: String,
    #[serde(default)]
    args: serde_json::Value,
    #[serde(default)]
    expect: serde_json::Value,
}

// ── Trace runner ───────────────────────────────────────────────────────────

pub struct TraceRunner {
    workdir: tempfile::TempDir,
    fs: Option<LocalFileSystem>,
    cost_base: CostBaseline,
}

impl TraceRunner {
    pub fn new() -> Result<Self, TraceError> {
        let workdir = tempfile::tempdir()?;
        Ok(Self {
            workdir,
            fs: None,
            cost_base: CostBaseline::default(),
        })
    }

    pub fn run_trace(&mut self, trace_path: &Path) -> Result<Vec<TraceEvent>, TraceError> {
        let file = fs::File::open(trace_path)?;
        let reader = BufReader::new(file);
        let mut events: Vec<TraceEvent> = Vec::new();
        let mut schema: Option<String> = None;
        let mut step: u64 = 0;

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let trace_line: TraceLine = serde_json::from_str(trimmed)?;
            let op = trace_line.op.clone();

            if op == OP_TRACE_META {
                if step != 0 {
                    return Err(TraceError::Protocol("trace_meta must be first op".into()));
                }
                let s = trace_line
                    .args
                    .get(KEY_SCHEMA)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let v = trace_line
                    .args
                    .get(KEY_VERSION)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if s != POOL_TRACE_SCHEMA && s != CLUSTER_TRACE_SCHEMA {
                    return Err(TraceError::Protocol(format!("unsupported schema: {s}")));
                }
                if v > TRACE_VERSION {
                    return Err(TraceError::Protocol(format!("unsupported version: {v}")));
                }
                schema = Some(s.to_string());
                events.push(TraceEvent {
                    step,
                    op,
                    cost: CostBaseline::default(),
                    fingerprint: None,
                    result: None,
                });
                step += 1;
                continue;
            }

            if schema.is_none() {
                return Err(TraceError::Protocol(
                    "trace_meta must precede all other ops".into(),
                ));
            }

            let cost_before = self.snapshot_cost();
            let result = self.dispatch_op(&op, &trace_line.args, &trace_line.expect)?;
            let cost_after = self.snapshot_cost();
            let cost_delta = CostBaseline::delta(&cost_after, &cost_before);
            let fingerprint = Some(self.state_fingerprint()?);

            events.push(TraceEvent {
                step,
                op,
                cost: cost_delta,
                fingerprint,
                result,
            });
            step += 1;
        }

        self.fs = None;
        Ok(events)
    }

    fn snapshot_cost(&self) -> CostBaseline {
        let mut cost = self.cost_base.clone();
        if let Some(ref fs) = self.fs {
            cost.accumulate(&CostBaseline::from_fs_stats(&fs.stats()));
        }
        cost
    }

    fn state_fingerprint(&self) -> Result<String, TraceError> {
        let fs = match &self.fs {
            Some(fs) => fs,
            None => return Ok(String::new()),
        };
        let mut hasher = blake3::Hasher::new();
        self.hash_namespace(fs, "/", &mut hasher)?;
        let snapshots = fs.list_snapshots();
        hasher.update(&(snapshots.len() as u64).to_le_bytes());
        for snap in &snapshots {
            hasher.update(snap.name.as_bytes());
            hasher.update(b"\x00");
        }
        let hash = hasher.finalize();
        Ok(hex::encode(hash.as_bytes()))
    }

    #[allow(clippy::only_used_in_recursion)]
    fn hash_namespace(
        &self,
        fs: &LocalFileSystem,
        path: &str,
        hasher: &mut blake3::Hasher,
    ) -> Result<(), TraceError> {
        let entries: Vec<NamespaceEntry> = fs
            .list_dir(path)
            .map_err(|e| TraceError::FileSystem(format!("list_dir {path}: {e}")))?;
        let mut sorted: Vec<_> = entries.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        for entry in &sorted {
            let name = String::from_utf8_lossy(&entry.name);
            let child_path = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };

            hasher.update(entry.name.as_slice());
            hasher.update(b"\x00");
            let kind_byte = match entry.kind() {
                NodeKind::Dir => 0u8,
                NodeKind::File => 1u8,
                NodeKind::Symlink => 2u8,
                _ => 3u8,
            };
            hasher.update(&[kind_byte]);

            match entry.kind() {
                NodeKind::Dir => {
                    self.hash_namespace(fs, &child_path, hasher)?;
                }
                NodeKind::File => {
                    if let Ok(data) = fs.read_file(&child_path) {
                        hasher.update(&(data.len() as u64).to_le_bytes());
                        hasher.update(&data);
                    }
                }
                NodeKind::Symlink => {
                    if let Ok(target) = fs.read_symlink(&child_path) {
                        hasher.update(&target);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn fs(&self) -> Result<&LocalFileSystem, TraceError> {
        self.fs
            .as_ref()
            .ok_or_else(|| TraceError::Protocol("pool not open".into()))
    }

    fn fs_mut(&mut self) -> Result<&mut LocalFileSystem, TraceError> {
        self.fs
            .as_mut()
            .ok_or_else(|| TraceError::Protocol("pool not open".into()))
    }

    fn dispatch_op(
        &mut self,
        op: &str,
        args: &serde_json::Value,
        expect: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, TraceError> {
        match op {
            OP_CREATE_POOL => {
                self.fs = None;
                let device_size = args
                    .get(KEY_DEVICE_SIZE_BYTES)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(128 * 1024 * 1024);
                let device_count = args
                    .get(KEY_DEVICE_COUNT)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2) as usize;
                let pool_dir = self.workdir.path().join("pool");
                fs::create_dir_all(&pool_dir)?;
                for i in 0..device_count {
                    let dev_path = pool_dir.join(format!("dev_{i}"));
                    let f = fs::File::create(&dev_path)?;
                    f.set_len(device_size)?;
                }
                let store_dir = pool_dir.join("store");
                fs::create_dir_all(&store_dir)?;
                let fs = LocalFileSystem::open_with_root_authentication_key(
                    &store_dir,
                    tidefs_local_object_store::StoreOptions::default(),
                    tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
                )
                .map_err(|e| TraceError::FileSystem(format!("create_pool: {e}")))?;
                self.fs = Some(fs);
                self.cost_base = CostBaseline::default();
                Ok(None)
            }

            OP_OPEN_POOL | OP_RESTART_POOL => {
                self.fs = None;
                let store_dir = self.workdir.path().join("pool").join("store");
                let fs = LocalFileSystem::open_with_root_authentication_key(
                    &store_dir,
                    tidefs_local_object_store::StoreOptions::default(),
                    tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
                )
                .map_err(|e| TraceError::FileSystem(format!("open_pool: {e}")))?;
                self.fs = Some(fs);
                Ok(None)
            }

            OP_CLOSE_POOL => {
                self.fs = None;
                Ok(None)
            }

            OP_ASSERT_FINGERPRINT => {
                let expected = expect
                    .get(KEY_FINGERPRINT)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        TraceError::Protocol(
                            "assert_fingerprint: missing expect.fingerprint".into(),
                        )
                    })?;
                let actual = self.state_fingerprint()?;
                if actual.is_empty() {
                    return Err(TraceError::Assertion(
                        "assert_fingerprint: pool not open".into(),
                    ));
                }
                if actual != expected {
                    return Err(TraceError::Assertion(format!(
                        "fingerprint mismatch: expected {expected}, got {actual}"
                    )));
                }
                Ok(None)
            }

            OP_CREATE_DATASET => {
                let name = get_string_arg(args, KEY_NAME)?;
                let path = format!("/{name}");
                let fs = self.fs_mut()?;
                fs.create_dir(&path, 0o755)
                    .map_err(|e| TraceError::FileSystem(format!("create_dataset {name}: {e}")))?;
                Ok(None)
            }

            OP_MKDIR => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs_mut()?;
                fs.create_dir(&path, 0o755)
                    .map_err(|e| TraceError::FileSystem(format!("mkdir {path}: {e}")))?;
                Ok(None)
            }

            OP_CREATE_FILE => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs_mut()?;
                fs.create_file(&path, 0o644)
                    .map_err(|e| TraceError::FileSystem(format!("create_file {path}: {e}")))?;
                Ok(None)
            }

            OP_PUT => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let value_b64 = get_string_arg(args, KEY_VALUE_B64)?;
                let data =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value_b64)?;
                let path = format!("/{dataset}/{key}");

                // Ensure parent directories exist.
                {
                    let fs = self.fs_mut()?;
                    ensure_parent_dir(fs, &path)?;
                }

                // Look up the file first; only create if it doesn't exist.
                // This avoids the replace_file-on-nonexistent -> create_file
                // double-attempt that can leave corrupt state on the store.
                {
                    let fs = self.fs()?;
                    if fs.lookup(&path).is_err() {
                        let _ = fs;
                        let fs = self.fs_mut()?;
                        fs.create_file(&path, 0o644).map_err(|e| {
                            TraceError::FileSystem(format!("put create {path}: {e}"))
                        })?;
                    }
                }

                let fs = self.fs_mut()?;
                fs.replace_file(&path, &data)
                    .map_err(|e| TraceError::FileSystem(format!("put write {path}: {e}")))?;
                Ok(None)
            }

            OP_GET => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let path = format!("/{dataset}/{key}");
                let fs = self.fs()?;
                let data = fs
                    .read_file(&path)
                    .map_err(|e| TraceError::FileSystem(format!("get {path}: {e}")))?;
                let value_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
                if let Some(expected) = expect.get(KEY_VALUE_B64).and_then(|v| v.as_str()) {
                    if value_b64 != expected {
                        return Err(TraceError::Assertion(format!(
                            "get {path}: expected {expected}, got {value_b64}"
                        )));
                    }
                }
                Ok(Some(serde_json::json!({KEY_VALUE_B64: value_b64})))
            }

            OP_WRITE_RANGE => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let offset = args.get(KEY_OFFSET).and_then(|v| v.as_u64()).unwrap_or(0);
                let data_b64 = get_string_arg(args, KEY_DATA_B64)?;
                let data =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data_b64)?;
                let path = format!("/{dataset}/{key}");
                let fs = self.fs_mut()?;
                let existing = fs.read_file(&path).unwrap_or_default();
                let new_len = (offset as usize).saturating_add(data.len());
                let mut buf = if new_len > existing.len() {
                    let mut b = existing;
                    b.resize(new_len, 0);
                    b
                } else {
                    existing
                };
                let end = (offset as usize).saturating_add(data.len());
                if end <= buf.len() {
                    buf[offset as usize..end].copy_from_slice(&data);
                }
                fs.replace_file(&path, &buf)
                    .map_err(|e| TraceError::FileSystem(format!("write_range {path}: {e}")))?;
                Ok(None)
            }

            OP_GET_RANGE => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let offset = args.get(KEY_OFFSET).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let length = args.get(KEY_LENGTH).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let path = format!("/{dataset}/{key}");
                let fs = self.fs()?;
                let data = fs
                    .read_file(&path)
                    .map_err(|e| TraceError::FileSystem(format!("get_range {path}: {e}")))?;
                let slice = if offset < data.len() {
                    &data[offset..std::cmp::min(offset.saturating_add(length), data.len())]
                } else {
                    &[]
                };
                let value_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, slice);
                if let Some(expected) = expect.get(KEY_VALUE_B64).and_then(|v| v.as_str()) {
                    if value_b64 != expected {
                        return Err(TraceError::Assertion(format!(
                            "get_range {path}: expected {expected}, got {value_b64}"
                        )));
                    }
                }
                Ok(Some(serde_json::json!({KEY_VALUE_B64: value_b64})))
            }

            OP_FSYNC => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let datasync = args
                    .get(KEY_DATASYNC)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let path = format!("/{dataset}/{key}");
                let fs = self.fs_mut()?;
                let result = if datasync {
                    fs.fsync_data_only_file(&path)
                } else {
                    fs.fsync_file(&path)
                };
                result.map_err(|e| TraceError::FileSystem(format!("fsync {path}: {e}")))?;
                Ok(None)
            }

            OP_CREATE_SNAPSHOT => {
                let name = get_string_arg(args, KEY_NAME)?;
                let fs = self.fs_mut()?;
                fs.create_snapshot(&name)
                    .map_err(|e| TraceError::FileSystem(format!("create_snapshot {name}: {e}")))?;
                Ok(None)
            }

            OP_DESTROY_SNAPSHOT => {
                let name = get_string_arg(args, KEY_NAME)?;
                let fs = self.fs_mut()?;
                fs.delete_snapshot(&name)
                    .map_err(|e| TraceError::FileSystem(format!("destroy_snapshot {name}: {e}")))?;
                Ok(None)
            }

            OP_UNLINK => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs_mut()?;
                fs.unlink(&path)
                    .or_else(|_| fs.remove_dir(&path))
                    .map_err(|e| TraceError::FileSystem(format!("unlink {path}: {e}")))?;
                Ok(None)
            }

            OP_RENAME => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let src = get_string_arg(args, KEY_SRC)?;
                let dst = get_string_arg(args, KEY_DST)?;
                let src_path = format!("/{dataset}/{src}");
                let dst_path = format!("/{dataset}/{dst}");
                let fs = self.fs_mut()?;
                fs.rename(&src_path, &dst_path, false).map_err(|e| {
                    TraceError::FileSystem(format!("rename {src_path} -> {dst_path}: {e}"))
                })?;
                Ok(None)
            }

            OP_REFLINK => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let src = get_string_arg(args, KEY_SRC)?;
                let dst = get_string_arg(args, KEY_DST)?;
                let src_path = format!("/{dataset}/{src}");
                let dst_path = format!("/{dataset}/{dst}");
                let fs = self.fs_mut()?;
                fs.reflink_file(&src_path, &dst_path).map_err(|e| {
                    TraceError::FileSystem(format!("reflink {src_path} -> {dst_path}: {e}"))
                })?;
                Ok(None)
            }

            OP_LOOKUP => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs()?;
                let inode_id = fs
                    .lookup(&path)
                    .map_err(|e| TraceError::FileSystem(format!("lookup {path}: {e}")))?;
                Ok(Some(serde_json::json!({"inode_id": inode_id.0})))
            }

            OP_READDIR => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs()?;
                let entries = fs
                    .list_dir(&path)
                    .map_err(|e| TraceError::FileSystem(format!("readdir {path}: {e}")))?;
                let names: Vec<String> = entries
                    .iter()
                    .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                    .collect();
                Ok(Some(serde_json::json!({KEY_NAMES_ARR: names})))
            }

            OP_WALK => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = args.get(KEY_PATH).and_then(|v| v.as_str()).unwrap_or("");
                let base = if ps.is_empty() {
                    format!("/{dataset}")
                } else {
                    format!("/{dataset}/{ps}")
                };
                let mut paths: Vec<String> = Vec::new();
                self.collect_paths(&base, &mut paths)?;
                Ok(Some(serde_json::json!({"paths": paths})))
            }

            OP_STAT => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let path = format!("/{dataset}/{ps}");
                let fs = self.fs()?;
                let record = fs
                    .stat(&path)
                    .map_err(|e| TraceError::FileSystem(format!("stat {path}: {e}")))?;
                Ok(Some(serde_json::json!({
                    "inode_id": record.inode_id.0, "kind": format!("{:?}", record.kind()),
                    "size": record.size, "nlink": record.nlink,
                })))
            }

            OP_STAT_BATCH => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let dir_path = get_string_arg(args, KEY_DIR_PATH)?;
                let path = format!("/{dataset}/{dir_path}");
                let fs = self.fs()?;
                let names_arr = args.get(KEY_NAMES).and_then(|v| v.as_array());
                let mut stats: Vec<serde_json::Value> = Vec::new();
                if let Some(names) = names_arr {
                    for name_val in names {
                        if let Some(name) = name_val.as_str() {
                            let full = format!("{path}/{name}");
                            match fs.stat(&full) {
                                Ok(record) => stats.push(serde_json::json!({
                                    "name": name, "inode_id": record.inode_id.0,
                                    "kind": format!("{:?}", record.kind()), "size": record.size,
                                })),
                                Err(_) => stats
                                    .push(serde_json::json!({"name": name, "error": "not found"})),
                            }
                        }
                    }
                }
                Ok(Some(serde_json::json!({"stats": stats})))
            }

            OP_SERVICE_BACKGROUND => {
                let max_tasks = args
                    .get(KEY_MAX_TASKS)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(8);
                let fs = self.fs_mut()?;
                for _ in 0..max_tasks {
                    match fs.commit_group_maintenance_tick() {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(_) => break,
                    }
                }
                Ok(None)
            }

            OP_STATX => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let path = format!("/{dataset}/{key}");
                let fs = self.fs()?;
                let attr = fs
                    .stat_attr(&path)
                    .map_err(|e| TraceError::FileSystem(format!("statx {path}: {e}")))?;
                let mask = args
                    .get(KEY_STATX_MASK)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let sync_flags = args
                    .get(KEY_STATX_SYNC_FLAGS)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let result = serde_json::json!({
                    "ino": attr.inode_id.0,
                    "generation": attr.generation.0,
                    "mode": attr.posix.mode,
                    "uid": attr.posix.uid,
                    "gid": attr.posix.gid,
                    "size": attr.posix.size,
                    "blocks": attr.posix.blocks_512,
                    "blksize": attr.posix.blksize,
                    "nlink": attr.posix.nlink,
                    "atime_ns": attr.posix.atime_ns,
                    "mtime_ns": attr.posix.mtime_ns,
                    "ctime_ns": attr.posix.ctime_ns,
                    "btime_ns": attr.posix.btime_ns,
                    "request_mask": mask,
                    "sync_flags": sync_flags,
                });
                Ok(Some(result))
            }

            OP_READAHEAD => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let offset = args.get(KEY_OFFSET).and_then(|v| v.as_u64()).unwrap_or(0);
                let count = args
                    .get(KEY_READAHEAD_COUNT)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let path = format!("/{dataset}/{key}");
                let fs = self.fs()?;
                match fs.read_file(&path) {
                    Ok(data) => {
                        let end = (offset as usize).saturating_add(count as usize);
                        let len = if end <= data.len() { end } else { data.len() };
                        let read_len = if (offset as usize) < data.len() {
                            len.saturating_sub(offset as usize)
                        } else {
                            0
                        };
                        Ok(Some(serde_json::json!({
                            "readahead_bytes": read_len,
                            "offset": offset,
                            "requested": count,
                        })))
                    }
                    Err(e) => Err(TraceError::FileSystem(format!("readahead {path}: {e}"))),
                }
            }

            OP_PAGE_CACHE_STATS => {
                let pc_hit = args.get(KEY_PC_HIT).and_then(|v| v.as_u64()).unwrap_or(0);
                let pc_miss = args.get(KEY_PC_MISS).and_then(|v| v.as_u64()).unwrap_or(0);
                let pc_populate = args
                    .get(KEY_PC_POPULATE)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let pc_prefetch = args
                    .get(KEY_PC_PREFETCH)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let pc_evict = args.get(KEY_PC_EVICT).and_then(|v| v.as_u64()).unwrap_or(0);
                let total = pc_hit.saturating_add(pc_miss);
                let hit_ratio_ppm = if total == 0 {
                    0u64
                } else {
                    (pc_hit as u128)
                        .saturating_mul(1_000_000)
                        .checked_div(total as u128)
                        .map_or(0, |v| v as u64)
                };
                Ok(Some(serde_json::json!({
                    "pc_hit": pc_hit,
                    "pc_miss": pc_miss,
                    "pc_populate": pc_populate,
                    "pc_prefetch": pc_prefetch,
                    "pc_evict": pc_evict,
                    "total_accesses": total,
                    "hit_ratio_ppm": hit_ratio_ppm,
                })))
            }

            other => Err(TraceError::Protocol(format!("unknown op: {other}"))),
        }
    }

    fn collect_paths(&self, base: &str, paths: &mut Vec<String>) -> Result<(), TraceError> {
        let fs = self.fs()?;
        match fs.list_dir(base) {
            Ok(entries) => {
                for entry in &entries {
                    let name = String::from_utf8_lossy(&entry.name);
                    let child = if base == "/" {
                        format!("/{name}")
                    } else {
                        format!("{base}/{name}")
                    };
                    paths.push(child.clone());
                    if entry.kind() == NodeKind::Dir {
                        self.collect_paths(&child, paths)?;
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if !err_str.contains("NotDirectory") {
                    return Err(TraceError::FileSystem(format!("collect_paths {base}: {e}")));
                }
            }
        }
        Ok(())
    }
}

// ── Free helper: ensure parent directory exists ────────────────────────────

fn ensure_parent_dir(fs: &mut LocalFileSystem, path: &str) -> Result<(), TraceError> {
    let path = path.trim_start_matches('/');
    if let Some(last_slash) = path.rfind('/') {
        let parent = &path[..last_slash];
        let segments: Vec<&str> = parent.split('/').collect();
        let mut built = String::new();
        for seg in &segments {
            if seg.is_empty() {
                continue;
            }
            built.push('/');
            built.push_str(seg);
            // Silently ignore if already exists.
            let _ = fs.create_dir(&built, 0o755);
        }
    }
    Ok(())
}

// ── JsonlTraceWriter ───────────────────────────────────────────────────────

pub struct JsonlTraceWriter {
    writer: Option<BufWriter<fs::File>>,
}

impl JsonlTraceWriter {
    pub fn new(path: &Path) -> Result<Self, TraceError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::File::create(path)?;
        Ok(Self {
            writer: Some(BufWriter::new(file)),
        })
    }

    pub fn write_op(&mut self, op: &serde_json::Value) -> Result<(), TraceError> {
        let writer = self.writer.as_mut().ok_or_else(|| {
            TraceError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "writer closed",
            ))
        })?;
        let json_str = sort_and_compact_json(op)?;
        writer.write_all(json_str.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), TraceError> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush()?;
        }
        Ok(())
    }
}

impl Drop for JsonlTraceWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// ── JSON utility ───────────────────────────────────────────────────────────

fn sort_and_compact_json(value: &serde_json::Value) -> Result<String, TraceError> {
    let sorted = sort_json_value(value);
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::new(&mut buf);
    sorted.serialize(&mut ser)?;
    String::from_utf8(buf)
        .map_err(|e| TraceError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

fn sort_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_json_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_value).collect())
        }
        other => other.clone(),
    }
}

// ── Trace file utilities ───────────────────────────────────────────────────

pub fn load_trace(path: &Path) -> Result<Vec<serde_json::Value>, TraceError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut ops: Vec<serde_json::Value> = Vec::new();
    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        ops.push(serde_json::from_str(trimmed)?);
    }
    Ok(ops)
}

pub fn save_trace(path: &Path, ops: &[serde_json::Value]) -> Result<(), TraceError> {
    let mut writer = JsonlTraceWriter::new(path)?;
    for op in ops {
        writer.write_op(op)?;
    }
    writer.close()?;
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, TraceError> {
    use sha2::{Digest, Sha256};
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(&hasher.finalize()))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn get_string_arg(args: &serde_json::Value, key: &str) -> Result<String, TraceError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| TraceError::Protocol(format!("missing arg: {key}")))
}

// ── TraceRecord ────────────────────────────────────────────────────────────

/// A single recorded trace operation with timing and COMMIT_GROUP context.
///
/// This is the typed counterpart to the raw `serde_json::Value` trace lines.
/// It adds `commit_group_id` for transaction-group correlation and `timestamp_ms` for
/// timing verification during replay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceRecord {
    pub op: String,
    pub args: serde_json::Value,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub commit_group_id: u64,
    #[serde(default)]
    pub timestamp_ms: u64,
}

impl TraceRecord {
    /// Create a new trace record with the current wall-clock time as `timestamp_ms`.
    pub fn new(
        op: &str,
        args: serde_json::Value,
        result: Option<serde_json::Value>,
        commit_group_id: u64,
    ) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            op: op.to_string(),
            args,
            result,
            commit_group_id,
            timestamp_ms,
        }
    }

    /// Create a TraceRecord with an explicit timestamp (useful for deterministic tests).
    pub fn with_timestamp(
        op: &str,
        args: serde_json::Value,
        result: Option<serde_json::Value>,
        commit_group_id: u64,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            op: op.to_string(),
            args,
            result,
            commit_group_id,
            timestamp_ms,
        }
    }

    /// Convert this record into the `TraceLine` format consumed by `TraceRunner`.
    fn to_trace_line(&self) -> serde_json::Value {
        let mut line = serde_json::json!({
            "op": self.op,
            "args": self.args,
        });
        if let Some(ref expect) = self.result {
            line.as_object_mut()
                .unwrap()
                .insert("expect".to_string(), expect.clone());
        }
        line
    }
}

// ── TraceOracleStats ───────────────────────────────────────────────────────

/// Accumulated statistics for trace oracle record and replay sessions.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceOracleStats {
    pub operations_recorded: u64,
    pub operations_replayed: u64,
    pub mismatches: u64,
    pub replay_time_ms: u64,
}

impl TraceOracleStats {
    fn record_succeeded(&mut self) {
        self.operations_recorded = self.operations_recorded.saturating_add(1);
    }

    fn replay_succeeded(&mut self, elapsed_ms: u64) {
        self.operations_replayed = self.operations_replayed.saturating_add(1);
        self.replay_time_ms = self.replay_time_ms.saturating_add(elapsed_ms);
    }

    fn replay_mismatch(&mut self, elapsed_ms: u64) {
        self.mismatches = self.mismatches.saturating_add(1);
        self.replay_time_ms = self.replay_time_ms.saturating_add(elapsed_ms);
    }
}

// ── TraceOracle ────────────────────────────────────────────────────────────

/// High-level trace oracle supporting record and replay modes.
///
/// # Record mode
///
/// ```ignore
/// let mut oracle = TraceOracle::begin_record(path)?;
/// oracle.record_op("put", &args, Some(&result), commit_group_id)?;
/// let stats = oracle.finish_record()?;
/// ```
///
/// # Replay mode
///
/// ```ignore
/// let mut oracle = TraceOracle::begin_replay(path)?;
/// let (events, stats) = oracle.replay_all(&mut runner)?;
/// ```
pub struct TraceOracle {
    stats: TraceOracleStats,
    state: TraceOracleState,
}

enum TraceOracleState {
    Record { writer: JsonlTraceWriter },
    Replay { records: Vec<TraceRecord> },
    Finished,
}

impl TraceOracle {
    // ── Record mode ──────────────────────────────────────────────────────

    /// Begin recording operations to a JSONL trace file.
    pub fn begin_record(path: &Path) -> Result<Self, TraceError> {
        let writer = JsonlTraceWriter::new(path)?;
        Ok(Self {
            stats: TraceOracleStats::default(),
            state: TraceOracleState::Record { writer },
        })
    }

    /// Record a single operation with its arguments, result, and COMMIT_GROUP id.
    ///
    /// The `result` is optional; pass `None` for operations that have no
    /// meaningful return value (e.g. `mkdir`, `unlink`).
    pub fn record_op(
        &mut self,
        op: &str,
        args: &serde_json::Value,
        result: Option<&serde_json::Value>,
        commit_group_id: u64,
    ) -> Result<(), TraceError> {
        match &mut self.state {
            TraceOracleState::Record { writer } => {
                let record = TraceRecord::new(op, args.clone(), result.cloned(), commit_group_id);
                let json_val = serde_json::to_value(&record).map_err(TraceError::Json)?;
                writer.write_op(&json_val)?;
                self.stats.record_succeeded();
                Ok(())
            }
            _ => Err(TraceError::Protocol(
                "TraceOracle: not in record mode".into(),
            )),
        }
    }

    /// Finish recording, flush the trace file, and return accumulated stats.
    pub fn finish_record(&mut self) -> Result<TraceOracleStats, TraceError> {
        match std::mem::replace(&mut self.state, TraceOracleState::Finished) {
            TraceOracleState::Record { mut writer } => {
                writer.close()?;
            }
            _ => {
                return Err(TraceError::Protocol(
                    "TraceOracle: not in record mode".into(),
                ));
            }
        }
        Ok(self.stats.clone())
    }

    // ── Replay mode ──────────────────────────────────────────────────────

    /// Begin replay by loading recorded operations from a JSONL trace file
    /// produced by `begin_record` / `record_op`.
    pub fn begin_replay(path: &Path) -> Result<Self, TraceError> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut records: Vec<TraceRecord> = Vec::new();

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let record: TraceRecord = serde_json::from_str(trimmed)?;
            records.push(record);
        }

        Ok(Self {
            stats: TraceOracleStats::default(),
            state: TraceOracleState::Replay { records },
        })
    }

    /// Replay all loaded records through the given `TraceRunner`, comparing
    /// each operation's result against the recorded expectation.
    ///
    /// Returns the full list of trace events and accumulated statistics.
    pub fn replay_all(
        &mut self,
        runner: &mut TraceRunner,
    ) -> Result<(Vec<TraceEvent>, TraceOracleStats), TraceError> {
        let records = match &self.state {
            TraceOracleState::Replay { records } => records.clone(),
            _ => {
                return Err(TraceError::Protocol(
                    "TraceOracle: not in replay mode".into(),
                ));
            }
        };

        // Build a temporary trace from the records and run through TraceRunner.
        let mut trace_ops: Vec<serde_json::Value> = Vec::new();
        for record in &records {
            trace_ops.push(record.to_trace_line());
        }

        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path().join("replay_trace.jsonl");
        save_trace(&temp_path, &trace_ops)?;

        let start = std::time::Instant::now();
        let events = match runner.run_trace(&temp_path) {
            Ok(events) => events,
            Err(TraceError::Assertion(_msg)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                self.stats.mismatches = self.stats.mismatches.saturating_add(1);
                self.stats.replay_time_ms = elapsed;
                return Ok((Vec::new(), self.stats.clone()));
            }
            Err(e) => return Err(e),
        };
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Compare replay events against recorded expectations.
        for (i, event) in events.iter().enumerate() {
            // Skip the trace_meta event (always step 0).
            if i == 0 && event.op == OP_TRACE_META {
                continue;
            }
            // Find the corresponding record (after meta offset).
            let rec_idx = if events.first().map(|e| e.op.as_str()) == Some(OP_TRACE_META) {
                i.saturating_sub(1)
            } else {
                i
            };

            if let Some(record) = records.get(rec_idx) {
                if record.result.is_some() {
                    let matched = event.result == record.result;
                    if !matched {
                        self.stats.replay_mismatch(0);
                    } else {
                        self.stats.replay_succeeded(0);
                    }
                } else {
                    self.stats.replay_succeeded(0);
                }
            } else {
                self.stats.replay_succeeded(0);
            }
        }

        // Count records (excluding trace_meta) that had no corresponding event.
        let event_count = events.iter().filter(|e| e.op != OP_TRACE_META).count();
        let record_count = records.iter().filter(|r| r.op != OP_TRACE_META).count();
        if event_count < record_count {
            let extra = (record_count - event_count) as u64;
            self.stats.mismatches = self.stats.mismatches.saturating_add(extra);
        }

        self.stats.replay_time_ms = elapsed_ms;

        Ok((events, self.stats.clone()))
    }

    /// Return a snapshot of the current statistics.
    pub fn stats(&self) -> &TraceOracleStats {
        &self.stats
    }
}

// ── TraceOracle tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod trace_oracle_tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // ── TraceRecord tests ──────────────────────────────────────────────

    #[test]
    fn trace_record_new_populates_timestamp() {
        let record = TraceRecord::new(
            "put",
            json!({"dataset": "ds", "key": "k"}),
            Some(json!({"value_b64": "AAAA"})),
            42,
        );
        assert_eq!(record.op, "put");
        assert_eq!(record.commit_group_id, 42);
        assert!(record.timestamp_ms > 0);
        assert!(record.result.is_some());
    }

    #[test]
    fn trace_record_with_timestamp() {
        let record =
            TraceRecord::with_timestamp("get", json!({"dataset": "ds", "key": "k"}), None, 7, 1000);
        assert_eq!(record.op, "get");
        assert_eq!(record.commit_group_id, 7);
        assert_eq!(record.timestamp_ms, 1000);
        assert!(record.result.is_none());
    }

    #[test]
    fn trace_record_serialization_roundtrip() {
        let record = TraceRecord::with_timestamp(
            "put",
            json!({"dataset": "ds", "key": "k", "value_b64": "AAAA"}),
            Some(json!({"written": 4})),
            3,
            5000,
        );
        let json_str = serde_json::to_string(&record).unwrap();
        let parsed: TraceRecord = serde_json::from_str(&json_str).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn trace_record_deserialize_with_defaults() {
        let json_str = r#"{"op":"mkdir","args":{"dataset":"ds","path":"a"}}"#;
        let record: TraceRecord = serde_json::from_str(json_str).unwrap();
        assert_eq!(record.op, "mkdir");
        assert_eq!(record.commit_group_id, 0);
        assert_eq!(record.timestamp_ms, 0);
        assert!(record.result.is_none());
    }

    #[test]
    fn trace_record_to_trace_line() {
        let record = TraceRecord::with_timestamp(
            "put",
            json!({"dataset": "ds", "key": "k"}),
            Some(json!({"value_b64": "QQ=="})),
            1,
            100,
        );
        let line = record.to_trace_line();
        assert_eq!(line["op"], "put");
        assert_eq!(line["args"]["dataset"], "ds");
        assert_eq!(line["expect"]["value_b64"], "QQ==");
    }

    #[test]
    fn trace_record_to_trace_line_no_result() {
        let record =
            TraceRecord::with_timestamp("mkdir", json!({"dataset": "ds", "path": "d"}), None, 0, 0);
        let line = record.to_trace_line();
        assert_eq!(line["op"], "mkdir");
        assert!(line.get("expect").is_none());
    }

    // ── TraceOracleStats tests ─────────────────────────────────────────

    #[test]
    fn stats_default_zero() {
        let s = TraceOracleStats::default();
        assert_eq!(s.operations_recorded, 0);
        assert_eq!(s.operations_replayed, 0);
        assert_eq!(s.mismatches, 0);
        assert_eq!(s.replay_time_ms, 0);
    }

    #[test]
    fn stats_accumulate() {
        let mut s = TraceOracleStats::default();
        s.record_succeeded();
        s.record_succeeded();
        s.replay_succeeded(10);
        s.replay_mismatch(5);
        s.replay_succeeded(15);
        assert_eq!(s.operations_recorded, 2);
        assert_eq!(s.operations_replayed, 2);
        assert_eq!(s.mismatches, 1);
        assert_eq!(s.replay_time_ms, 30);
    }

    #[test]
    fn stats_saturation() {
        let mut s = TraceOracleStats {
            operations_recorded: u64::MAX,
            ..Default::default()
        };
        s.record_succeeded();
        assert_eq!(s.operations_recorded, u64::MAX);
    }

    // ── TraceOracle record/replay round-trip tests ──────────────────────

    #[test]
    fn record_replay_roundtrip_basic() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("basic.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(
                OP_CREATE_POOL,
                &json!({"device_count": 1, "device_size_bytes": 4194304}),
                None,
                1,
            )
            .unwrap();
        oracle
            .record_op(OP_CREATE_DATASET, &json!({"name": "ds"}), None, 2)
            .unwrap();
        let record_stats = oracle.finish_record().unwrap();
        assert_eq!(record_stats.operations_recorded, 3);

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (events, replay_stats) = oracle.replay_all(&mut runner).unwrap();

        assert!(replay_stats.operations_replayed >= 2);
        assert_eq!(replay_stats.mismatches, 0);
        assert!(events.len() >= 3);
    }

    #[test]
    fn record_replay_with_results() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("results.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(
                OP_CREATE_POOL,
                &json!({"device_count": 1, "device_size_bytes": 4194304}),
                None,
                1,
            )
            .unwrap();
        oracle
            .record_op(OP_CREATE_DATASET, &json!({"name": "ds"}), None, 2)
            .unwrap();
        oracle
            .record_op(
                OP_PUT,
                &json!({"dataset": "ds", "key": "f1", "value_b64": "SGVsbG8="}),
                None,
                3,
            )
            .unwrap();
        oracle
            .record_op(OP_GET, &json!({"dataset": "ds", "key": "f1"}), None, 4)
            .unwrap();
        oracle.finish_record().unwrap();

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (_events, replay_stats) = oracle.replay_all(&mut runner).unwrap();

        assert_eq!(replay_stats.mismatches, 0);
        assert!(replay_stats.operations_replayed > 0);
    }

    #[test]
    fn injected_mismatch_detected() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("mismatch.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(
                OP_CREATE_POOL,
                &json!({"device_count": 1, "device_size_bytes": 4194304}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(OP_CREATE_DATASET, &json!({"name": "ds"}), None, 0)
            .unwrap();
        oracle
            .record_op(
                OP_PUT,
                &json!({"dataset": "ds", "key": "f1", "value_b64": "SGVsbG8="}),
                None,
                0,
            )
            .unwrap();
        // Inject a wrong expected result for get.
        oracle
            .record_op(
                OP_GET,
                &json!({"dataset": "ds", "key": "f1"}),
                Some(&json!({"value_b64": "V1JPTkc="})),
                0,
            )
            .unwrap();
        oracle.finish_record().unwrap();

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (_events, replay_stats) = oracle.replay_all(&mut runner).unwrap();

        assert!(
            replay_stats.mismatches > 0,
            "should detect injected mismatch, got mismatches={}",
            replay_stats.mismatches
        );
    }

    #[test]
    fn concurrent_operations_ordering() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("concurrent.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(
                OP_CREATE_POOL,
                &json!({"device_count": 1, "device_size_bytes": 4194304}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(OP_CREATE_DATASET, &json!({"name": "ds"}), None, 0)
            .unwrap();

        let keys = ["a", "b", "c", "d", "e", "f", "g", "h"];
        for (i, key) in keys.iter().enumerate() {
            oracle
                .record_op(
                    OP_PUT,
                    &json!({"dataset": "ds", "key": key, "value_b64": "AAAA"}),
                    None,
                    i as u64,
                )
                .unwrap();
        }
        oracle.finish_record().unwrap();

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (_events, replay_stats) = oracle.replay_all(&mut runner).unwrap();

        assert_eq!(replay_stats.mismatches, 0);
    }

    #[test]
    fn small_trace_ops() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("large.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(
                OP_CREATE_POOL,
                &json!({"device_count": 1, "device_size_bytes": 4194304}),
                None,
                0,
            )
            .unwrap();
        oracle
            .record_op(OP_CREATE_DATASET, &json!({"name": "ds"}), None, 0)
            .unwrap();

        // 10 puts exercises the full record/replay pipeline without
        // dominating test time. Larger-scale testing runs via
        // `tests/trace_scenarios.rs` (ignored tests).
        const OP_COUNT: usize = 10;
        for i in 0..OP_COUNT {
            oracle
                .record_op(
                    OP_PUT,
                    &json!({
                        "dataset": "ds",
                        "key": format!("k{i}"),
                        "value_b64": "AAAA"
                    }),
                    None,
                    i as u64,
                )
                .unwrap();
        }
        let record_stats = oracle.finish_record().unwrap();
        assert_eq!(record_stats.operations_recorded, (OP_COUNT + 3) as u64);

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (_events, replay_stats) = oracle.replay_all(&mut runner).unwrap();

        assert!(replay_stats.operations_replayed > 0);
        assert!(replay_stats.replay_time_ms > 0);
    }

    #[test]
    fn empty_trace_replay() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("empty.jsonl");
        std::fs::write(&trace_path, "").unwrap();

        let mut oracle = TraceOracle::begin_replay(&trace_path).unwrap();
        let mut runner = TraceRunner::new().unwrap();
        let (events, stats) = oracle.replay_all(&mut runner).unwrap();
        assert!(events.is_empty());
        assert_eq!(stats.operations_replayed, 0);
        assert_eq!(stats.mismatches, 0);
    }

    #[test]
    fn stats_serialization_roundtrip() {
        let stats = TraceOracleStats {
            operations_recorded: 100,
            operations_replayed: 95,
            mismatches: 5,
            replay_time_ms: 1234,
        };
        let json_str = serde_json::to_string(&stats).unwrap();
        let parsed: TraceOracleStats = serde_json::from_str(&json_str).unwrap();
        assert_eq!(stats, parsed);
    }

    #[test]
    fn begin_record_creates_file() {
        let dir = TempDir::new().unwrap();
        let trace_path = dir.path().join("new.jsonl");

        let mut oracle = TraceOracle::begin_record(&trace_path).unwrap();
        oracle
            .record_op(
                OP_TRACE_META,
                &json!({"schema": POOL_TRACE_SCHEMA, "version": TRACE_VERSION}),
                None,
                0,
            )
            .unwrap();
        oracle.finish_record().unwrap();

        assert!(trace_path.exists());
        let content = std::fs::read_to_string(&trace_path).unwrap();
        assert!(content.contains("trace_meta"));
    }
}
