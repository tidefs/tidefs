//! Backend abstraction for replaying one JSONL trace through multiple engines.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tidefs_model_core::{ModelFs, ModelOutput, ModelPath, ModelRequest, ModelStep};
use tidefs_types_vfs_core::{CompletionDisposition, CompletionStatus, Errno};

use crate::protocol::*;
use crate::{get_string_arg, load_trace, TraceError, TraceRunner};

pub const BACKEND_MODEL: &str = "model";
pub const BACKEND_LOCAL_RUNTIME: &str = "local_runtime";
pub const BACKEND_EXPECTATIONS_VERSION: u64 = 1;

/// Parsed form of one authoritative JSONL trace line.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TraceOperation {
    pub op: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub expect: Value,
}

/// Normalized operation completion used for backend-to-backend comparison.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BackendCompletion {
    pub status: String,
    pub disposition: String,
    pub errno: String,
    pub completed_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BackendCompletion {
    fn success(completed_bytes: u64, result: Option<Value>) -> Self {
        Self {
            status: "success".into(),
            disposition: "final".into(),
            errno: Errno::SUCCESS.name().into(),
            completed_bytes,
            result,
            error: None,
        }
    }

    fn failed(error: impl Into<String>) -> Self {
        Self {
            status: "failed".into(),
            disposition: "final".into(),
            errno: "EIO".into(),
            completed_bytes: 0,
            result: None,
            error: Some(error.into()),
        }
    }

    fn from_model(step: &ModelStep, result: Option<Value>) -> Self {
        Self {
            status: completion_status_name(step.completion.status).into(),
            disposition: completion_disposition_name(step.completion.disposition).into(),
            errno: step.completion.errno.name().into(),
            completed_bytes: step.completion.completed_bytes,
            result,
            error: None,
        }
    }
}

/// One backend's observation for a single trace operation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BackendStep {
    pub backend: String,
    pub operation_index: usize,
    pub operation: TraceOperation,
    pub completion: BackendCompletion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Expected backend result recorded in `traces/MANIFEST.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BackendExpectation {
    pub expected_fingerprint: String,
    #[serde(default)]
    pub expected_completions: Vec<ExpectedCompletion>,
}

/// Expected completion for one operation index.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ExpectedCompletion {
    pub operation_index: usize,
    pub op: String,
    pub completion: BackendCompletion,
}

/// Fingerprints captured at the mismatch point.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FingerprintDelta {
    pub model: Option<String>,
    pub runtime: Option<String>,
}

/// A semantic mismatch between the model and local-runtime backends.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TraceMismatch {
    pub operation_index: usize,
    pub request: TraceOperation,
    pub model_completion: BackendCompletion,
    pub runtime_completion: BackendCompletion,
    pub fingerprint_delta: FingerprintDelta,
    pub replay_command: String,
}

impl fmt::Display for TraceMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace mismatch at operation {} ({})\nrequest: {}\nmodel completion: {}\nruntime completion: {}\nfingerprint delta: model={:?} runtime={:?}\nreplay: {}",
            self.operation_index,
            self.request.op,
            serde_json::to_string(&self.request).unwrap_or_else(|_| "<unserializable>".into()),
            serde_json::to_string(&self.model_completion)
                .unwrap_or_else(|_| "<unserializable>".into()),
            serde_json::to_string(&self.runtime_completion)
                .unwrap_or_else(|_| "<unserializable>".into()),
            self.fingerprint_delta.model,
            self.fingerprint_delta.runtime,
            self.replay_command
        )
    }
}

/// Full comparison output for one trace.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TraceComparison {
    pub trace_path: PathBuf,
    pub model_events: Vec<BackendStep>,
    pub runtime_events: Vec<BackendStep>,
    pub mismatches: Vec<TraceMismatch>,
}

impl TraceComparison {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty()
    }

    #[must_use]
    pub fn final_fingerprint(&self, backend: &str) -> Option<&str> {
        let events = match backend {
            BACKEND_MODEL => &self.model_events,
            BACKEND_LOCAL_RUNTIME => &self.runtime_events,
            _ => return None,
        };
        events
            .iter()
            .rev()
            .find_map(|event| event.fingerprint.as_deref())
    }
}

/// Backend boundary for deterministic trace execution.
pub trait TraceBackend {
    fn name(&self) -> &'static str;
    fn apply(
        &mut self,
        operation_index: usize,
        operation: &TraceOperation,
    ) -> Result<BackendStep, TraceError>;
    fn finish(&mut self) -> Result<(), TraceError> {
        Ok(())
    }
}

/// Existing local-runtime harness exposed through the backend trait.
pub struct LocalRuntimeTraceBackend {
    runner: TraceRunner,
}

impl LocalRuntimeTraceBackend {
    pub fn new() -> Result<Self, TraceError> {
        Ok(Self {
            runner: TraceRunner::new()?,
        })
    }
}

impl TraceBackend for LocalRuntimeTraceBackend {
    fn name(&self) -> &'static str {
        BACKEND_LOCAL_RUNTIME
    }

    fn apply(
        &mut self,
        operation_index: usize,
        operation: &TraceOperation,
    ) -> Result<BackendStep, TraceError> {
        let result = self
            .runner
            .dispatch_op(&operation.op, &operation.args, &operation.expect);
        let (completion, fingerprint) = match result {
            Ok(result) => {
                let completed_bytes =
                    infer_completed_bytes(&operation.op, &operation.args, &result);
                (
                    BackendCompletion::success(
                        completed_bytes,
                        normalize_runtime_result(&operation.op, result),
                    ),
                    Some(self.runner.state_fingerprint()?),
                )
            }
            Err(TraceError::Protocol(err)) => return Err(TraceError::Protocol(err)),
            Err(err) => (
                BackendCompletion::failed(err.to_string()),
                self.runner.state_fingerprint().ok(),
            ),
        };

        Ok(BackendStep {
            backend: self.name().into(),
            operation_index,
            operation: operation.clone(),
            completion,
            fingerprint,
        })
    }

    fn finish(&mut self) -> Result<(), TraceError> {
        self.runner.fs = None;
        Ok(())
    }
}

/// Pure executable model backend from `tidefs-model-core`.
#[derive(Default)]
pub struct ModelTraceBackend {
    live: Option<ModelFs>,
    persisted: Option<ModelFs>,
}

impl ModelTraceBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn live(&self) -> Result<&ModelFs, TraceError> {
        self.live
            .as_ref()
            .ok_or_else(|| TraceError::Protocol("model pool not open".into()))
    }

    fn live_mut(&mut self) -> Result<&mut ModelFs, TraceError> {
        self.live
            .as_mut()
            .ok_or_else(|| TraceError::Protocol("model pool not open".into()))
    }

    fn apply_model_request(
        &mut self,
        operation: &TraceOperation,
        request: ModelRequest,
        result_override: Option<Value>,
    ) -> Result<(BackendCompletion, Option<String>), TraceError> {
        let step = self
            .live_mut()?
            .apply(request)
            .map_err(|err| TraceError::Assertion(format!("model invariant: {err}")))?;
        let result = result_override.or_else(|| model_output_result(operation, &step.output));
        let completion = BackendCompletion::from_model(&step, result);
        let fingerprint = Some(step.fingerprint.to_hex());
        Ok((completion, fingerprint))
    }
}

impl TraceBackend for ModelTraceBackend {
    fn name(&self) -> &'static str {
        BACKEND_MODEL
    }

    fn apply(
        &mut self,
        operation_index: usize,
        operation: &TraceOperation,
    ) -> Result<BackendStep, TraceError> {
        let (completion, fingerprint) = match operation.op.as_str() {
            OP_CREATE_POOL => {
                let fs = ModelFs::new();
                self.persisted = Some(fs.clone());
                self.live = Some(fs);
                (
                    BackendCompletion::success(0, None),
                    Some(self.live()?.fingerprint().to_hex()),
                )
            }
            OP_OPEN_POOL => {
                let fs = self.persisted.clone().unwrap_or_default();
                self.live = Some(fs);
                (
                    BackendCompletion::success(0, None),
                    Some(self.live()?.fingerprint().to_hex()),
                )
            }
            OP_RESTART_POOL => {
                if let Some(live) = &self.live {
                    self.persisted = Some(live.clone());
                }
                let fs = self.persisted.clone().unwrap_or_default();
                self.live = Some(fs);
                (
                    BackendCompletion::success(0, None),
                    Some(self.live()?.fingerprint().to_hex()),
                )
            }
            OP_CLOSE_POOL => {
                self.persisted = self.live.take();
                (BackendCompletion::success(0, None), None)
            }
            OP_CREATE_DATASET => {
                let name = dataset_name(&operation.args)?;
                self.apply_model_request(
                    operation,
                    ModelRequest::Mkdir {
                        path: model_path(&format!("/{name}"))?,
                    },
                    None,
                )?
            }
            OP_MKDIR => {
                let path = dataset_relative_path(&operation.args, KEY_PATH)?;
                self.apply_model_request(operation, ModelRequest::Mkdir { path }, None)?
            }
            OP_CREATE_FILE => {
                let path = dataset_relative_path(&operation.args, KEY_PATH)?;
                self.apply_model_request(operation, ModelRequest::Create { path }, None)?
            }
            OP_PUT => self.apply_put(operation)?,
            OP_GET => self.apply_get(operation, None)?,
            OP_WRITE_RANGE => {
                let path = dataset_relative_path(&operation.args, KEY_KEY)?;
                let offset = operation
                    .args
                    .get(KEY_OFFSET)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let data = decode_arg_b64(&operation.args, KEY_DATA_B64)?;
                self.apply_model_request(
                    operation,
                    ModelRequest::Write {
                        path,
                        offset,
                        bytes: data,
                    },
                    None,
                )?
            }
            OP_GET_RANGE => {
                let offset = operation
                    .args
                    .get(KEY_OFFSET)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let length = operation
                    .args
                    .get(KEY_LENGTH)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                self.apply_get(operation, Some((offset, length)))?
            }
            OP_UNLINK => {
                let path = dataset_relative_path(&operation.args, KEY_PATH)?;
                self.apply_model_request(operation, ModelRequest::Unlink { path }, None)?
            }
            OP_RENAME => {
                let from = dataset_relative_path(&operation.args, KEY_SRC)?;
                let to = dataset_relative_path(&operation.args, KEY_DST)?;
                self.apply_model_request(operation, ModelRequest::Rename { from, to }, None)?
            }
            OP_LOOKUP => {
                let path = dataset_relative_path(&operation.args, KEY_PATH)?;
                self.apply_model_request(
                    operation,
                    ModelRequest::GetAttr { path },
                    Some(json!({"found": true})),
                )?
            }
            OP_STAT => {
                let path = dataset_relative_path(&operation.args, KEY_PATH)?;
                let attr = self.live()?.attr(&path).map_err(model_errno_error)?;
                self.apply_model_request(
                    operation,
                    ModelRequest::GetAttr { path },
                    Some(json!({
                        "kind": model_kind_name(attr.kind),
                        "nlink": attr.nlink,
                        "size": attr.size
                    })),
                )?
            }
            OP_SERVICE_BACKGROUND => (
                BackendCompletion::success(0, None),
                Some(self.live()?.fingerprint().to_hex()),
            ),
            OP_ASSERT_FINGERPRINT => {
                let fingerprint = self.live()?.fingerprint().to_hex();
                let expected = operation
                    .expect
                    .get(BACKEND_MODEL)
                    .and_then(|v| v.get(KEY_FINGERPRINT))
                    .and_then(Value::as_str)
                    .or_else(|| {
                        operation
                            .expect
                            .get(KEY_FINGERPRINT)
                            .and_then(Value::as_str)
                    });
                if let Some(expected) = expected {
                    if expected != fingerprint {
                        (
                            BackendCompletion::failed(format!(
                                "model fingerprint mismatch: expected {expected}, got {fingerprint}"
                            )),
                            Some(fingerprint),
                        )
                    } else {
                        (BackendCompletion::success(0, None), Some(fingerprint))
                    }
                } else {
                    (BackendCompletion::success(0, None), Some(fingerprint))
                }
            }
            OP_CREATE_SNAPSHOT | OP_DESTROY_SNAPSHOT | OP_REFLINK | OP_READDIR | OP_WALK
            | OP_STAT_BATCH | OP_STATX | OP_READAHEAD | OP_PAGE_CACHE_STATS => (
                BackendCompletion {
                    status: "unsupported".into(),
                    disposition: "unsupported".into(),
                    errno: Errno::EOPNOTSUPP.name().into(),
                    completed_bytes: 0,
                    result: None,
                    error: None,
                },
                self.live.as_ref().map(|fs| fs.fingerprint().to_hex()),
            ),
            other => return Err(TraceError::Protocol(format!("unknown op: {other}"))),
        };

        Ok(BackendStep {
            backend: self.name().into(),
            operation_index,
            operation: operation.clone(),
            completion,
            fingerprint,
        })
    }

    fn finish(&mut self) -> Result<(), TraceError> {
        self.persisted = self.live.take().or_else(|| self.persisted.take());
        Ok(())
    }
}

impl ModelTraceBackend {
    fn apply_put(
        &mut self,
        operation: &TraceOperation,
    ) -> Result<(BackendCompletion, Option<String>), TraceError> {
        let path = dataset_relative_path(&operation.args, KEY_KEY)?;
        ensure_model_parent_dirs(self.live_mut()?, &path)?;
        if matches!(self.live()?.attr(&path), Err(Errno::ENOENT)) {
            self.live_mut()?
                .apply(ModelRequest::Create { path: path.clone() })
                .map_err(|err| TraceError::Assertion(format!("model invariant: {err}")))?;
        }
        self.live_mut()?
            .apply(ModelRequest::Truncate {
                path: path.clone(),
                size: 0,
            })
            .map_err(|err| TraceError::Assertion(format!("model invariant: {err}")))?;
        let bytes = decode_arg_b64(&operation.args, KEY_VALUE_B64)?;
        self.apply_model_request(
            operation,
            ModelRequest::Write {
                path,
                offset: 0,
                bytes,
            },
            None,
        )
    }

    fn apply_get(
        &mut self,
        operation: &TraceOperation,
        range: Option<(u64, u64)>,
    ) -> Result<(BackendCompletion, Option<String>), TraceError> {
        let path = dataset_relative_path(&operation.args, KEY_KEY)?;
        let (offset, length) = match range {
            Some(range) => range,
            None => {
                let attr = self.live()?.attr(&path).map_err(model_errno_error)?;
                (0, attr.size)
            }
        };
        self.apply_model_request(
            operation,
            ModelRequest::Read {
                path,
                offset,
                length,
            },
            None,
        )
    }
}

/// Run one trace through a specific backend.
pub fn run_trace_with_backend<B: TraceBackend + ?Sized>(
    backend: &mut B,
    trace_path: &Path,
) -> Result<Vec<BackendStep>, TraceError> {
    let values = load_trace(trace_path)?;
    let mut events = Vec::new();
    let mut saw_meta = false;

    for (operation_index, value) in values.into_iter().enumerate() {
        let operation: TraceOperation = serde_json::from_value(value)?;
        if operation.op == OP_TRACE_META {
            if saw_meta || operation_index != 0 {
                return Err(TraceError::Protocol("trace_meta must be first op".into()));
            }
            validate_trace_meta(&operation)?;
            saw_meta = true;
            events.push(BackendStep {
                backend: backend.name().into(),
                operation_index,
                operation,
                completion: BackendCompletion::success(0, None),
                fingerprint: None,
            });
            continue;
        }
        if !saw_meta {
            return Err(TraceError::Protocol(
                "trace_meta must precede all other ops".into(),
            ));
        }
        events.push(backend.apply(operation_index, &operation)?);
    }

    backend.finish()?;
    Ok(events)
}

/// Compare the model and local-runtime backends over the same JSONL trace.
pub fn compare_model_and_runtime_trace(trace_path: &Path) -> Result<TraceComparison, TraceError> {
    let mut model = ModelTraceBackend::new();
    let mut runtime = LocalRuntimeTraceBackend::new()?;
    let model_events = run_trace_with_backend(&mut model, trace_path)?;
    let runtime_events = run_trace_with_backend(&mut runtime, trace_path)?;
    let replay_command = replay_command(trace_path);
    let mut mismatches = Vec::new();

    let by_index = steps_by_index(&model_events, &runtime_events);
    for (operation_index, model_step, runtime_step) in by_index {
        if model_step.operation.op == OP_TRACE_META {
            continue;
        }
        if model_step.completion != runtime_step.completion {
            mismatches.push(TraceMismatch {
                operation_index,
                request: model_step.operation.clone(),
                model_completion: model_step.completion.clone(),
                runtime_completion: runtime_step.completion.clone(),
                fingerprint_delta: FingerprintDelta {
                    model: model_step.fingerprint.clone(),
                    runtime: runtime_step.fingerprint.clone(),
                },
                replay_command: replay_command.clone(),
            });
        }
    }

    Ok(TraceComparison {
        trace_path: trace_path.to_path_buf(),
        model_events,
        runtime_events,
        mismatches,
    })
}

/// Verify manifest-recorded model/local expectations for one trace.
pub fn verify_backend_expectations(
    trace_path: &Path,
    expectations: &BTreeMap<String, BackendExpectation>,
) -> Result<TraceComparison, TraceError> {
    let comparison = compare_model_and_runtime_trace(trace_path)?;
    if let Some(first) = comparison.mismatches.first() {
        return Err(TraceError::Assertion(first.to_string()));
    }

    for (backend, expectation) in expectations {
        let events = match backend.as_str() {
            BACKEND_MODEL => &comparison.model_events,
            BACKEND_LOCAL_RUNTIME => &comparison.runtime_events,
            other => {
                return Err(TraceError::Protocol(format!(
                    "unknown backend expectation: {other}"
                )));
            }
        };
        let actual = events
            .iter()
            .rev()
            .find_map(|event| event.fingerprint.as_deref())
            .unwrap_or("");
        if actual != expectation.expected_fingerprint {
            return Err(TraceError::Assertion(format!(
                "{backend} fingerprint mismatch: expected {}, got {}",
                expectation.expected_fingerprint, actual
            )));
        }
        for expected in &expectation.expected_completions {
            let actual_step = events
                .iter()
                .find(|event| event.operation_index == expected.operation_index)
                .ok_or_else(|| {
                    TraceError::Assertion(format!(
                        "{backend} missing completion for operation {}",
                        expected.operation_index
                    ))
                })?;
            if actual_step.operation.op != expected.op {
                return Err(TraceError::Assertion(format!(
                    "{backend} operation {} op mismatch: expected {}, got {}",
                    expected.operation_index, expected.op, actual_step.operation.op
                )));
            }
            if actual_step.completion != expected.completion {
                return Err(TraceError::Assertion(format!(
                    "{backend} operation {} completion mismatch: expected {}, got {}",
                    expected.operation_index,
                    serde_json::to_string(&expected.completion)?,
                    serde_json::to_string(&actual_step.completion)?
                )));
            }
        }
    }

    Ok(comparison)
}

#[must_use]
pub fn replay_command(trace_path: &Path) -> String {
    format!(
        "cargo run -p tidefs-xtask -- check-trace-oracle --compare-trace {}",
        trace_path.display()
    )
}

fn validate_trace_meta(operation: &TraceOperation) -> Result<(), TraceError> {
    let schema = operation
        .args
        .get(KEY_SCHEMA)
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = operation
        .args
        .get(KEY_VERSION)
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if schema != POOL_TRACE_SCHEMA {
        return Err(TraceError::Protocol(format!(
            "backend comparison requires {POOL_TRACE_SCHEMA}, got {schema}"
        )));
    }
    if version > TRACE_VERSION {
        return Err(TraceError::Protocol(format!(
            "unsupported version: {version}"
        )));
    }
    Ok(())
}

fn steps_by_index<'a>(
    model_events: &'a [BackendStep],
    runtime_events: &'a [BackendStep],
) -> Vec<(usize, &'a BackendStep, &'a BackendStep)> {
    model_events
        .iter()
        .filter_map(|model| {
            runtime_events
                .iter()
                .find(|runtime| runtime.operation_index == model.operation_index)
                .map(|runtime| (model.operation_index, model, runtime))
        })
        .collect()
}

fn dataset_name(args: &Value) -> Result<String, TraceError> {
    args.get(KEY_NAME)
        .and_then(Value::as_str)
        .or_else(|| args.get(KEY_DATASET).and_then(Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| TraceError::Protocol("missing dataset name".into()))
}

fn dataset_relative_path(args: &Value, key: &str) -> Result<ModelPath, TraceError> {
    let dataset = get_string_arg(args, KEY_DATASET)?;
    let relative = get_string_arg(args, key)?;
    let path = if relative.is_empty() {
        format!("/{dataset}")
    } else {
        format!(
            "/{}/{}",
            dataset.trim_matches('/'),
            relative.trim_start_matches('/')
        )
    };
    model_path(&path)
}

fn model_path(path: &str) -> Result<ModelPath, TraceError> {
    ModelPath::parse_absolute(path).map_err(|errno| {
        TraceError::Protocol(format!("invalid model path {path}: {}", errno.name()))
    })
}

fn decode_arg_b64(args: &Value, key: &str) -> Result<Vec<u8>, TraceError> {
    let encoded = get_string_arg(args, key)?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(TraceError::Base64)
}

fn ensure_model_parent_dirs(fs: &mut ModelFs, path: &ModelPath) -> Result<(), TraceError> {
    let components = path.components();
    if components.len() <= 1 {
        return Ok(());
    }
    let mut parent = Vec::new();
    for component in &components[..components.len() - 1] {
        parent.push(component.clone());
        let path =
            ModelPath::from_components(parent.iter().map(String::as_str)).map_err(|errno| {
                TraceError::Protocol(format!("invalid parent path: {}", errno.name()))
            })?;
        if matches!(fs.attr(&path), Err(Errno::ENOENT)) {
            fs.apply(ModelRequest::Mkdir { path })
                .map_err(|err| TraceError::Assertion(format!("model invariant: {err}")))?;
        }
    }
    Ok(())
}

fn model_output_result(operation: &TraceOperation, output: &ModelOutput) -> Option<Value> {
    match operation.op.as_str() {
        OP_GET | OP_GET_RANGE => output.as_bytes().map(|bytes| {
            json!({
                KEY_VALUE_B64: base64::engine::general_purpose::STANDARD.encode(bytes)
            })
        }),
        OP_LOOKUP => output.as_attr().map(|_| json!({"found": true})),
        OP_STAT => output.as_attr().map(|attr| {
            json!({
                "kind": model_kind_name(attr.kind),
                "nlink": attr.nlink,
                "size": attr.size
            })
        }),
        _ => None,
    }
}

fn normalize_runtime_result(op: &str, result: Option<Value>) -> Option<Value> {
    match op {
        OP_LOOKUP => result.map(|_| json!({"found": true})),
        OP_STAT => result.and_then(|value| {
            Some(json!({
                "kind": value.get("kind")?.clone(),
                "nlink": value.get("nlink")?.clone(),
                "size": value.get("size")?.clone()
            }))
        }),
        _ => result,
    }
}

fn infer_completed_bytes(op: &str, args: &Value, result: &Option<Value>) -> u64 {
    match op {
        OP_PUT => decoded_len(args, KEY_VALUE_B64),
        OP_WRITE_RANGE => decoded_len(args, KEY_DATA_B64),
        OP_GET | OP_GET_RANGE => result
            .as_ref()
            .and_then(|value| value.get(KEY_VALUE_B64))
            .and_then(Value::as_str)
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
            })
            .map_or(0, |bytes| bytes.len() as u64),
        _ => 0,
    }
}

fn decoded_len(args: &Value, key: &str) -> u64 {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .map_or(0, |bytes| bytes.len() as u64)
}

fn completion_status_name(status: CompletionStatus) -> &'static str {
    match status {
        CompletionStatus::Success => "success",
        CompletionStatus::Failed => "failed",
        CompletionStatus::Unsupported => "unsupported",
        CompletionStatus::TimedOut => "timed_out",
        CompletionStatus::Cancelled => "cancelled",
        CompletionStatus::Deferred => "deferred",
        CompletionStatus::Rejected => "rejected",
    }
}

fn completion_disposition_name(disposition: CompletionDisposition) -> &'static str {
    match disposition {
        CompletionDisposition::Final => "final",
        CompletionDisposition::Retryable => "retryable",
        CompletionDisposition::Deferred => "deferred",
        CompletionDisposition::Unsupported => "unsupported",
    }
}

fn model_kind_name(kind: tidefs_model_core::ModelNodeKind) -> &'static str {
    match kind {
        tidefs_model_core::ModelNodeKind::Directory => "Dir",
        tidefs_model_core::ModelNodeKind::File => "File",
    }
}

fn model_errno_error(errno: Errno) -> TraceError {
    TraceError::FileSystem(format!("model operation failed with {}", errno.name()))
}
