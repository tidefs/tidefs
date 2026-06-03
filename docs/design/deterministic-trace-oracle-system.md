# Deterministic Trace Oracle System Design

Maturity: **design-spec** for the deterministic trace oracle system that
provides a cross-implementation semantic regression oracle by replaying
JSONL trace files against tempdir-backed `LocalFileSystem` instances with
per-step IO cost delta tracking and BLAKE3-256 state fingerprints.

This document closes Forgejo issue #1552.

Authoritative protocol and crate: `crates/tidefs-trace-oracle/`.
Companion spec: `docs/DETERMINISTIC_TRACE_ORACLE_DESIGN.md` (P2 spec).

## 1. Motivation

TideFS needs a regression oracle that survives implementation changes. The
inline test suite tests individual functions but provides no baseline asserting
that filesystem semantics are preserved when internal algorithms change. The
Python reference implementation (v0.262) has a working trace oracle; this
gate.

The trace oracle provides:

- A **semantic contract** encoded as JSONL trace files with deterministic replay.
- **Cross-implementation confidence** that Rust semantics match the Python reference.
- **Cost transparency** via per-step IO delta tracking (read/write ops, bytes).
- **Trace minimization** that reduces failing traces to minimal reproducers.
- **Golden corpus** with manifest-driven integrity verification.

## 2. Architecture Overview

```
                        ┌──────────────────────────────┐
                        │     traces/MANIFEST.json      │
                        │  (sha256 + expected_fingerprint)│
                        └──────────────┬───────────────┘
                                       │ verify_trace_corpus()
                                       ▼
┌─────────────────┐    load_trace()    ┌──────────────────┐
│  traces/golden/  │ ────────────────► │   TraceRunner    │
│  *.jsonl files   │                   │                  │
└─────────────────┘                   │  ┌────────────┐  │
                                      │  │ LocalFS     │  │
                                      │  │ (tempdir)   │  │
                                      │  └────────────┘  │
                                      │        │         │
                                      │  per-step        │
                                      │  BLAKE3-256 FP   │
                                      │  + CostBaseline  │
                                      │        │         │
                                      │  Vec<TraceEvent> │
                                      └────────┬─────────┘
                                               │
                                               ▼
                                        fingerprint match?
```

The system consists of five coupled components:

1. **Wire Protocol** (`protocol.rs`): Op name constants, schema identifiers,
   JSON key constants. This is the cross-implementation contract.
2. **Trace Runner** (`lib.rs`): Replays JSONL traces against a tempdir-backed
   `LocalFileSystem`, capturing per-step IO cost deltas and BLAKE3-256 state
   fingerprints.
3. **Manifest Verifier** (`manifest.rs`): Loads `traces/MANIFEST.json`,
   verifies sha256 of each trace file, replays pool traces, and compares
   final fingerprints against expected values.
4. **Trace Minimizer** (`minimize.rs`): Three-phase algorithm that reduces
   failing traces to minimal reproducers.
5. **Golden Corpus** (`traces/golden/`): Deterministic trace scenarios with
   sha256-locked content and known-good fingerprints.

## 3. Wire Protocol

### 3.1 Schema Identifiers

```
POOL_TRACE_SCHEMA    = "pool_trace_v1"     // Single-pool traces (in scope)
CLUSTER_TRACE_SCHEMA = "cluster_trace_v1"  // Distributed traces (deferred)
TRACE_VERSION        = 1
```

### 3.2 JSONL Encoding Rules

Traces use JSON Lines with the following deterministic encoding constraints:

- `serde_json` with key-sorted, compact output: `{"op":"...","args":{...}}`
- No whitespace after `:` or `,`.
- Lines starting with `#` are comments and skipped.
- Blank lines are skipped.
- Every trace MUST begin with `trace_meta` declaring schema and version.
- Binary values are base64-encoded (RFC 4648 standard alphabet, no padding
  relaxation).

sorts object keys into `BTreeMap` order before serialization.

### 3.3 Value Encoding

|---|---|---|
| `fingerprint` | Hex string (64 chars) | Lowercase hex |

### 3.4 Op Catalog (20 ops across 6 families)

**Control ops** (pool lifecycle):

| Op | Args | Semantics |
|---|---|---|
| `trace_meta` | `schema`, `version` | Required first op. Hard error on mismatch. |
| `create_pool` | `device_count`, `device_size_bytes`, `bootstrap_b64` | Fresh pool with N temp-file devices. Resets cost base. |
| `open_pool` | (none) | Open existing pool from disk. |
| `restart_pool` | (none) | Close then reopen pool. Tests persistence. |
| `close_pool` | (none) | Flush and close pool. |
| `assert_fingerprint` | `expect.fingerprint` | Assert current BLAKE3-256 fingerprint matches. |

**Namespace ops:**

| Op | Args | Semantics |
|---|---|---|
| `create_dataset` | `name` | Create named dataset in pool. |
| `mkdir` | `dataset`, `path` | Create directory (with parent chain). |
| `create_file` | `dataset`, `path` | Create empty file (with parent chain). |
| `unlink` | `dataset`, `key` | Remove file or empty directory. |
| `rename` | `dataset`, `src`, `dst` | Atomic rename within dataset. |
| `reflink` | `dataset`, `src`, `dst` | Copy-on-write clone. |
| `lookup` | `dataset`, `key` | Resolve path to node kind + metadata. |

**File data ops:**

| Op | Args | Semantics |
|---|---|---|
| `put` | `dataset`, `key`, `value_b64` | Full-file write (base64 value). |
| `get` | `dataset`, `key`, `expect.value_b64` | Full-file read with optional assertion. |
| `write_range` | `dataset`, `key`, `offset`, `data_b64` | Range write at offset. |
| `get_range` | `dataset`, `key`, `offset`, `length`, `expect.data_b64` | Range read with optional assertion. |

**Snapshot ops:**

| Op | Args | Semantics |
|---|---|---|
| `create_snapshot` | `dataset` | Create named snapshot. |
| `destroy_snapshot` | `dataset` | Destroy snapshot. |

**Directory/introspection ops:**

| Op | Args | Semantics |
|---|---|---|
| `readdir` | `dataset`, `dir_path`, `start_after`, `max_entries` | Paginated directory listing. |
| `walk` | `dataset`, `start_after?`, `max_tasks?` | Full recursive namespace walk. |
| `stat` | `dataset`, `key` | Single-node stat. |
| `stat_batch` | `dataset`, `names` | Batch stat for multiple paths. |

**Maintenance ops:**

| Op | Args | Semantics |
|---|---|---|
| `service_background` | (none) | Trigger COMMIT_GROUP maintenance tick. |

## 4. Core Data Structures

### 4.1 CostBaseline

```rust
pub struct CostBaseline {
    pub read_ops: u64,
    pub write_ops: u64,
    pub flush_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}
```

The cost model captures five dimensions of IO activity. `delta(after, before)`
computes a per-step delta using saturating subtraction. `accumulate()` adds
another baseline in-place.

`from_fs_stats(stats: &FileSystemStats)` derives a cost estimate from
filesystem-level statistics: each inode and snapshot counts as one write op,
and inode count × 512 bytes estimates total data written.

**Design rationale:** Saturating arithmetic prevents overflow panics in
long-running traces. The delta model isolates per-op costs, enabling
regression detection: if a refactoring doubles the write-byte cost for `put`,
that shows as a delta deviation.

### 4.2 TraceEvent

```rust
pub struct TraceEvent {
    pub step: u64,                    // Monotonic step counter
    pub op: String,                   // Wire-stable op name
    pub cost: CostBaseline,           // Cumulative cost after this op
    pub fingerprint: Option<String>,  // BLAKE3-256 hex (computed every N ops)
    pub result: Option<serde_json::Value>,  // Op return value
}
```

`step` is a monotonic counter incremented per successfully executed op.
`fingerprint` carries the BLAKE3-256 state hash computed from `walk()` output
sorted canonically. It is computed after `assert_fingerprint`, `put`,
`restart_pool`, and `close_pool` ops — and optionally after every op for
debug traces.

### 4.3 TraceLine (Raw Input)

```rust
struct TraceLine {
    op: String,
    args: serde_json::Value,     // default = {}
    expect: serde_json::Value,   // default = {}
}
```

Each JSONL line deserializes into this struct. `args` provides operation
parameters; `expect` specifies optional post-execution assertions.

### 4.4 Manifest

```rust
pub struct Manifest {
    pub manifest_version: u64,       // Must be 1
    pub generated_by: String,        // Tool/version tag
    pub items: Vec<ManifestItem>,
}

pub struct ManifestItem {
    pub id: String,                  // e.g., "smoke_churn_pool"
    pub description: String,
    pub kind: String,                // "pool" | "cluster"
    pub path: String,                // Relative to repo root
    pub schema: String,              // "pool_trace_v1" | "cluster_trace_v1"
    pub sha256: String,              // Hex sha256 of trace file
    pub expected_fingerprint: String, // BLAKE3-256 hex
}
```

The manifest is the single source of truth for corpus integrity. Each entry
records the trace file's sha256 and expected final fingerprint. Verification
compares both and reports failures separately: a sha256 mismatch means the
trace file was corrupted; a fingerprint mismatch means replay semantics
diverged.

### 4.5 TraceResult

```rust
pub struct TraceResult {
    pub id: String,
    pub passed: bool,
    pub events: Option<Vec<TraceEvent>>,
    pub error: Option<String>,
    pub sha256_ok: bool,
}
```

Per-entry verification result. `passed` is true only when both sha256 and
fingerprint match. `events` captures the full replay trace for debugging.
`sha256_ok` is tracked independently so callers can distinguish content
integrity failures from semantic divergences.

### 4.6 JsonlTraceWriter

```rust
pub struct JsonlTraceWriter {
    writer: Option<BufWriter<fs::File>>,
}
```

Streaming JSONL writer with deterministic output:
- `write_op()` sorts keys, serializes compactly, appends `\n`, and flushes.
- `Drop` calls `close()` to prevent silent data loss.

### 4.7 MinimizerContext and MinimizeResult

```rust
pub struct MinimizerContext {
    pub trace_id: String,
    pub trace_path: PathBuf,
    pub output_dir: PathBuf,
}

pub struct MinimizeResult {
    pub original_op_count: usize,
    pub minimized_op_count: usize,
    pub output_path: PathBuf,
}
```

`MinimizerContext` parameterizes the minimizer with the failing trace location
and output directory. `MinimizeResult` records the reduction achieved.

## 5. TraceRunner Algorithm

### 5.1 Lifecycle

```
new() → run_trace(path) → [events]
         │
         ├─ 1. Parse JSONL lines (skip comments/blanks)
         ├─ 3. For each subsequent op:
         │      ├─ Dispatch to LocalFileSystem method
         │      ├─ Capture IO cost delta
         │      ├─ Check expect assertions
         │      └─ Compute fingerprint at checkpoint ops
         └─ 4. Return Vec<TraceEvent>
```

### 5.2 Op Dispatch Map

The `run_trace()` method dispatches op names to `LocalFileSystem` calls:

| Op | LocalFileSystem Call | Return Value |
|---|---|---|
| `create_pool` | `LocalFileSystem::create()` | `pool_id: u64` |
| `open_pool` | `LocalFileSystem::open()` | `pool_id: u64` |
| `restart_pool` | Close then open | `pool_id: u64` |
| `close_pool` | Drop `LocalFileSystem` | `null` |
| `create_dataset` | `create_dataset(name)` | `dataset_id` |
| `mkdir` | `create_dir(path, 0o755)` | `null` |
| `create_file` | `create_file(path)` | `null` |
| `put` | `write_file(key, decoded_value)` | `bytes_written` |
| `get` | `read_file(key)` → base64 encode | `value_b64` |
| `write_range` | `write_range(key, offset, data)` | `bytes_written` |
| `get_range` | `read_range(key, offset, length)` → base64 | `data_b64` |
| `unlink` | `unlink(key)` | `null` |
| `rename` | `rename(src, dst)` | `null` |
| `reflink` | `reflink(src, dst)` | `null` |
| `create_snapshot` | `create_snapshot(dataset)` | `snapshot_name` |
| `destroy_snapshot` | `destroy_snapshot(snapshot_name)` | `null` |
| `lookup` | `lookup(key)` | `{kind, metadata}` |
| `readdir` | `read_dir(dir_path)` | `[{name, kind}]` |
| `walk` | Recursive walk via `read_dir()` | `[{path, kind}]` |
| `stat` | `stat(key)` | `{kind, size, ...}` |
| `stat_batch` | Iterated `stat()` | `[{key, stat}]` |
| `service_background` | `commit_group_maintenance_tick()` | `null` |
| `assert_fingerprint` | `compute_fingerprint()` | `fingerprint` |

### 5.3 Fingerprint Computation

The fingerprint is a BLAKE3-256 hash computed from the deterministic
canonical representation of pool state:

```
fingerprint = BLAKE3-256(canonical_state_string)

canonical_state_string =
  sorted_walk_output
  + sorted_snapshot_list
  + sorted_object_sizes
```

`walk_output` is a sorted list of `(path, kind, size)` tuples from a
recursive `walk()` of the pool. The sorting is lexical by path, ensuring
the same logical state produces the same byte string regardless of
internal hash table ordering.

**Why BLAKE3-256:** BLAKE3 is chosen over SHA-256 for three reasons:
(1) it is faster (~1.5 cycles/byte on Zen 4 vs ~11 for SHA-256), reducing
fingerprint overhead in debug traces; (2) its 256-bit output provides
128-bit collision resistance, sufficient for trace deduplication; (3) it is
a single dependency already used elsewhere in TideFS.

### 5.4 Cost Tracking

After each op execution, the runner captures the current `FileSystemStats`
and computes a delta against the previous baseline:

```
1. before = fs.stats() or zero baseline
2. execute_op()
3. after = fs.stats()
4. delta = CostBaseline::delta(after, before)
5. cumulative.accumulate(delta)
6. emit TraceEvent { cost: cumulative.clone(), ... }
```

The `from_fs_stats()` function maps filesystem statistics to cost dimensions:
- Each inode and snapshot counts as a write operation (object creation).
- Inode count × 512 estimates data bytes written (approximation; exact byte
  counting would require instrumenting every write path).

## 6. Golden Trace Corpus

### 6.1 Corpus Structure

```
traces/
  MANIFEST.json           # Manifest with sha256 + expected fingerprints
  golden/
    smoke_churn/
      pool_trace.jsonl    # 9 put ops + assert + restart
      cluster_trace.jsonl # Deferred (cluster trace placeholder)
    smoke_storm/
      pool_trace.jsonl    # 24 put ops + assert + restart
      cluster_trace.jsonl # Deferred
```

### 6.2 Scenario Definitions

**smoke_churn** (9 puts): Basic lifecycle — create pool, create dataset, put
keys k0.0..k2.2, assert fingerprint, restart, re-assert fingerprint.

**smoke_storm** (24 puts): Higher write volume — 3 groups × 8 puts,
exercising more internal shard/segment code paths.

### 6.3 Trace Generation Contract

Golden traces are generated by `tests/trace_scenarios.rs` (ignored tests,
run manually). Contract:

1. All values come from a fixed constant sequence (no PRNG — literal base64
   strings in test code).
2. The generation test writes bare ops, replays them to capture the
   fingerprint, then appends `assert_fingerprint` and `restart_pool` +
   re-assert.
3. Output is written to `traces/golden/<scenario>/pool_trace.jsonl`.
4. The test prints sha256 and fingerprint for manual manifest update.

This is intentionally no-PRNG: the trace corpus must produce identical
output on every machine, every time. A seeded PRNG adds complexity without
benefit when the scenario set is small.

## 7. Trace Minimization Algorithm

When a trace fails during replay (fingerprint mismatch or assertion failure),
the minimizer reduces it to the smallest reproducer that still fails.

### 7.1 Phase 1: Binary Search (Prefix Minimization)

```
Input:  ops[0..n] that fails replay
Output: ops[0..lo] where lo is minimal failing prefix

lo = 1, hi = n
while lo < hi:
    mid = lo + (hi - lo) / 2
    if replay(ops[0..mid]) == Ok: lo = mid + 1  # prefix passes
    else:                          hi = mid      # prefix fails
return ops[0..lo]
```

This finds the exact op where failure first manifests. Binary search runs in
O(log n) replay calls. On a 1000-op trace, worst case is ~10 replays.

**Edge case:** If `replay(ops[0..1])` fails, `lo` stays at 1 and the result
is a 1-op reproducer (plus `trace_meta`).

### 7.2 Phase 2: Operation Simplification

For each op in the minimized prefix, attempt to reduce its parameters:

**Payload reduction** (`put` / `write_range`): Decode the base64 payload. If
longer than 4 bytes, replace with a 4-byte zero payload. Re-test. If still
failing, keep the reduced version; otherwise, retain the original.

**Device size halving** (`create_pool`): Halve `device_size_bytes` with a
floor of 1 MiB (minimum viable pool size). Re-test.

Both simplifications use the same pattern: clone the op, modify a single
field, test, and keep the reduced version only if the failure persists.

### 7.3 Phase 3: Redundant-Op Removal

Iterate through ops and attempt to remove each one:

```
i = 0
while i < len(ops):
    if op[i] is meta/pool_control: skip (i += 1)
    candidate = ops without op[i]
    if replay(candidate) fails:
        ops = candidate    # Keep reduced, re-examine same index
    else:
        i += 1             # Op was essential
```

Protected ops (never removed): `trace_meta`, `create_pool`, `open_pool`,
`close_pool`, `assert_fingerprint`. These are structural — removing them
would produce an invalid trace, not a meaningful reproducer.

### 7.4 Output

The minimized trace is written to `traces/golden/minimized/<id>.jsonl` with
`trace_meta` prepended. The caller receives `MinimizeResult` with the
reduction ratio.

### 7.5 Algorithm Properties

| Property | Value |
|---|---|
| Phase 1 complexity | O(log n) replays |
| Phase 2 complexity | O(k) replays (k = op count after phase 1) |
| Phase 3 complexity | O(k) replays worst-case |
| Total | O(k + log n) replays |
| Soundness | Every minimized trace preserves the original failure |
| Completeness | Not guaranteed minimal (NP-hard in general); heuristic best-effort |

## 8. Integration Points

### 8.1 LocalFileSystem Dependency

The `TraceRunner` wraps `LocalFileSystem` directly. Each op name maps to a
concrete method call. The runner calls `ensure_parent_dir()` before file/dir
creation ops — this creates intermediate directories with `create_dir(path,
0o755)` and silently ignores `AlreadyExists` errors.

**Isolation:** Each `TraceRunner` instance creates a `tempfile::TempDir` and
constructs a `LocalFileSystem` within it. The tempdir is cleaned up on drop.
No production device backends (ublk, kernel block device) are used.

### 8.2 Manifest Verification Pipeline

```
verify_trace_corpus(repo_root, manifest) → Vec<TraceResult>
  for each ManifestItem where kind == "pool":
    1. sha256_file(trace_path) == item.sha256          → sha256_ok
    2. TraceRunner::new() → run_trace(trace_path)       → Vec<TraceEvent>
    3. events.last().fingerprint == item.expected_fingerprint → passed
```

Cluster traces (`kind != "pool"`) are skipped with `passed=true` and a note.
This is not a failure — cluster trace support is explicitly deferred.

### 8.3 xtask Integration

The `tidefs-xtask check-trace-oracle` subcommand wraps `verify_trace_corpus()`:

1. Locates repo root.
2. Loads `traces/MANIFEST.json`.
3. Calls `verify_trace_corpus()`.
4. Prints per-entry results with pass/fail/skip counts.
5. Exits non-zero on any failure.


### 8.4 Crate Dependency Graph

```
tidefs-trace-oracle
  ├── tidefs-local-filesystem    (op dispatch target)
  ├── tidefs-local-object-store   (indirect, via local-filesystem)
  ├── tidefs-types-vfs-core       (NodeKind for walk/stat)
  ├── serde + serde_json          (JSONL parsing/serialization)
  ├── sha2                        (sha256 for manifest verification)
  ├── blake3 =1.5.5               (state fingerprinting)
  ├── base64 =0.22                (binary value encoding)
  └── tempfile                    (isolated pool storage)
```

## 9. Error Taxonomy

`TraceError` covers six failure domains:

| Variant | Source | Example |
|---|---|---|
| `Io` | File I/O | Missing trace file, permission denied |
| `Json` | JSON parsing | Malformed JSONL line |
| `Base64` | Base64 decoding | Invalid base64 in `value_b64` |
| `FileSystem` | LocalFileSystem calls | `create_dataset` on existing name |
| `Protocol` | Trace structure | Missing `trace_meta`, unknown op |
| `Assertion` | `expect` mismatch | `get` returned wrong value |
| `Minimize` | Minimizer logic | Replay function panicked |

All variants implement `Display` and `Error`. `From` impls cover `Io`,
`Json`, and `Base64` for `?` propagation.

## 10. Determinism Guarantees

The trace oracle provides the following determinism contracts:

1. **Trace replay**: Running the same `pool_trace.jsonl` through
   `TraceRunner::run_trace()` on the same binary produces identical
   `Vec<TraceEvent>`, including step counts, cost deltas, and fingerprints.

2. **Fingerprint stability**: The BLAKE3-256 fingerprint is computed from
   a canonical sorted walk of the pool namespace. Internal hash table
   ordering does not affect the output.

3. **JsonlTraceWriter**: `write_op()` produces byte-identical JSONL for
   equivalent `serde_json::Value` inputs, regardless of insertion order,
   thanks to `sort_and_compact_json()`.

4. **Golden trace generation**: Trace scenario tests use literal base64
   strings and explicit op sequences — no PRNG, no system time, no hostname.

**Non-guarantees:**

- Fingerprints are NOT stable across `LocalFileSystem` implementation
  changes. An algorithm change that alters internal metadata layout may
  produce a different fingerprint. This is by design — fingerprint mismatch
  is exactly the signal the oracle detects.
- Cost baselines are approximate (derived from filesystem stats, not
  instrumented IO paths). Small cost deltas (±1 op) are not reliable
  regression signals.
- SHA-256 of trace files may change when `serde_json` serialization
  behavior changes across Rust versions.

## 11. Tradeoffs & Design Decisions

### 11.1 JSONL vs Binary Format

**Decision:** JSON Lines.

| Factor | JSONL | Binary (e.g., CBOR) |
|---|---|---|
| Human readability | ✓ grep/diff/`cat` | ✗ Requires tooling |
| Cross-language portability | ✓ Universal | ✓ Universal |
| Deterministic encoding | Requires key sorting | Requires canonical CBOR |
| Parsing overhead | Higher | Lower |
| File size | Larger (base64 blobs) | Smaller |

For a design-spec test oracle, human readability outweighs performance. Trace
files are typically < 100 KB; parsing overhead is negligible compared to
filesystem IO in replay.

### 11.2 BLAKE3-256 vs SHA-256 for Fingerprints

**Decision:** BLAKE3-256.

BLAKE3-256 provides the same 256-bit output size as SHA-256 but is ~7× faster
on x86-64. Fingerprint computation runs on every `assert_fingerprint` and
optionally every op in debug mode; the speed difference matters for developer
workflows. BLAKE3-256's 128-bit collision resistance is sufficient: the trace
corpus will contain at most thousands of traces, making collision probability
negligible (~10⁻¹⁵ for 10⁶ traces).

### 11.3 Tempdir vs In-Memory Pool

**Decision:** Tempdir-backed `LocalFileSystem`.

In-memory pools would be faster but would not exercise the same code paths as
production (disk I/O, page cache, file descriptor management). Tempdirs use
real filesystem syscalls and provide a more realistic test surface. The
cleanup is automatic via `TempDir::drop()`.

### 11.4 Cost Estimation vs Precise Instrumentation

**Decision:** Derive costs from `FileSystemStats`.

Precise per-op byte counting would require instrumenting every `write()`,
`read()`, and `flush()` call in `LocalFileSystem`. The stats-based approach
is:
- Zero-overhead: no additional bookkeeping in the hot path.
- Approximate: inode count × 512 is a heuristic, not a measurement.
- Sufficient: regression detection cares about order-of-magnitude changes,
  not single-byte deviations.

If precise cost tracking becomes necessary, an `InstrumentedLocalFileSystem`
wrapper can be added without changing the trace protocol.

### 11.5 No-PRNG Trace Generation

**Decision:** Use literal values in scenario tests, not seeded PRNG.

A seeded PRNG would require both Rust and Python implementations to produce
identical byte sequences from the same seed — a cross-language compatibility
burden. Literal base64 strings in test code are simpler, more transparent,
and trivially portable. For larger corpora, a deterministic generator that
outputs JSONL directly (bypassing the cross-language PRNG problem) can be
added.

## 12. Non-Claims (Explicit Boundaries)

- Cluster trace support (`cluster_trace_v1`) is deferred until the distributed
  runtime is implemented. Only `pool_trace_v1` is in scope.
- The golden trace corpus currently contains two scenarios (smoke_churn,
  smoke_storm). Expansion to crash-injection, snapshot-rollback, and
  reflink-clone scenarios is deferred to successor issues.
- Phase 2 and 3 minimizer heuristics may need tuning based on real-world
  failure patterns. The current payload-reduction-to-4-bytes and
  device-size-halving strategies are reasonable defaults.
- Cross-implementation comparison (Rust fingerprint vs Python fingerprint)
  is deferred until both implementations produce identical fingerprints for
  the same traces.
- Integration with chaos/corruption campaigns is deferred to a successor
  issue that wires fault-injected traces into the golden corpus.
- Integration with xfstests is deferred; the trace oracle is a complementary
  testing surface, not a replacement for POSIX conformance testing.
- Pool creation uses temp-file devices; production device backends are not
  used in trace replay.
- The `service_background` op triggers a single COMMIT_GROUP tick; its exact behavior
  (number of cleaned objects, freed bytes) is not asserted.



```
cargo test -p tidefs-trace-oracle          # Unit tests (trace I/O roundtrip)
cargo test -p tidefs-trace-oracle -- --ignored --nocapture  # Regenerate golden traces
tidefs-xtask check-trace-oracle            # Manifest-driven corpus verification
```

`check-trace-oracle` verifies:
1. `traces/MANIFEST.json` is valid JSON with `manifest_version: 1`.
2. Every pool trace entry's sha256 matches the trace file on disk.
3. `TraceRunner` replays each pool trace and produces the expected fingerprint.
4. Cluster trace entries are skipped (not failures).

## 14. Future Directions

1. **Crash-injection traces:** A `fault` field in `create_pool` args that
   injects controlled failures (IO errors, partial writes) at specific steps.
2. **Cluster trace support:** Adding `cluster_trace_v1` ops for multi-node
   scenarios (membership changes, quorum writes, rebuild).
3. **Comparison mode:** A `compare-traces` xtask that replays the same trace
   through two different `LocalFileSystem` backends and diffs fingerprints.
4. **Online trace capture:** A `--trace-output` flag on the FUSE daemon that
   records live operations as JSONL for later regression testing.
5. **Fingerprint diff viewer:** A tool that replays a trace through two
   different binaries and shows the exact op where fingerprints diverge.
