# Deterministic Trace Oracle System (P2 spec)

Maturity: **design-spec** for the deterministic trace oracle system that
provides a cross-implementation semantic regression oracle by replaying
JSONL trace files against tempdir-backed LocalFileSystem instances.

This document closes Forgejo issue #1174.

## 1. Motivation

TideFS currently lacks a cross-implementation regression oracle. The inline
test suite (`crates/tidefs-local-filesystem/src/tests.rs`, 5410 lines) tests
individual functions but provides no baseline asserting that filesystem
semantics are preserved when internal algorithms change. There is no mechanism
kernel-space behaviour matches userspace.

The Python reference implementation (v0.262) has a working trace oracle:
`TraceRunner` replays JSONL trace files deterministically, records per-step
IO cost deltas, produces deterministic logical fingerprints, and supports
embedded `expect` assertions. A golden trace corpus with `MANIFEST.json`
tracks each trace's sha256 and expected fingerprint. A `minimize_trace.py`
algorithm reduces failing traces to minimal reproducers.

This design ports that system to Rust and integrates it into the TideFS

- A **semantic contract** that survives implementation changes.
- Confidence that Rust semantics match the Python reference.
- A regression suite that catches bugs inline tests miss.

## 2. Relationship to Existing Types

| Current state | Replaced by | Migration path |
|---|---|---|
| Python `trace_io.py` TraceRunner (v0.262 reference) | Rust `tidefs-trace-oracle` crate with identical semantic surface | Port op dispatch from `semantic_ops_io.py` to `LocalFileSystem` method calls |
| Python `trace_protocol.py` op name constants | Rust `trace_protocol` module with identical string constants | Copy wire-stable op name strings as `&'static str` constants |
| Python `trace_io.py` JsonlTraceWriter | Rust `JsonlTraceWriter` struct in `tidefs-trace-oracle` | Port write/flush/close with `BufWriter<File>` and deterministic JSON serialization |
| Python `minimize_trace.py` (v0.262) | Rust `TraceMinimizer` in `tidefs-trace-oracle` | Port binary search, op simplification, redundant-op removal |
| Inline tests in `tests.rs` (5410 lines) | Golden trace corpus under `traces/golden/` | Gradual extraction: each new test can emit a trace; existing tests unaffected |
| No cross-implementation oracle | `verify-trace-corpus` xtask gate | Added as `check-trace-oracle` xtask subcommand |

## 3. JSONL Trace Format

### 3.1 Canonical encoding

Traces are stored as JSON Lines (JSONL): one JSON object per line, terminated
by `\n`. This format is append-friendly, human-readable, line-diffable, and
trivially portable across implementations.

**Encoding rules:**

- `json.dumps(sort_keys=True, separators=(",", ":"))` -- keys sorted, no
  whitespace after `:` or `,`.
- Lines starting with `#` are comments and skipped by the reader.
- Blank lines are skipped.
- Every trace MUST begin with a `trace_meta` op declaring schema and version.

### 3.2 Schema identifiers

```
POOL_TRACE_SCHEMA    = "pool_trace_v1"
CLUSTER_TRACE_SCHEMA = "cluster_trace_v1"
```

TideFS currently only supports `pool_trace_v1`. Cluster traces are deferred
until the distributed runtime is implemented.

### 3.3 Common JSON keys

| Key | Type | Description |
|---|---|---|
| `op` | string | Operation name (wire-stable, see section 4). |
| `args` | object | Operation arguments. |
| `expect` | object | Optional expected values asserted after execution. |

### 3.4 Value encoding

Binary values (file contents, bootstrap bytes) are base64-encoded in the
`value_b64`, `data_b64`, and `bootstrap_b64` fields using standard RFC 4648

### 3.5 Example trace

```jsonl
{"op":"trace_meta","args":{"schema":"pool_trace_v1","version":1}}
{"op":"create_pool","args":{"bootstrap_b64":"d...","device_count":2,"device_size_bytes":33554432}}
{"args":{"name":"ds"},"op":"create_dataset"}
{"args":{"dataset":"ds","path":"dir"},"op":"mkdir"}
{"args":{"dataset":"ds","path":"dir/f"},"op":"create_file"}
{"args":{"dataset":"ds","key":"dir/f","value_b64":"SGVsbG8gV29ybGQh"},"op":"put"}
{"expect":{"value_b64":"SGVsbG8gV29ybGQh"},"op":"get","args":{"dataset":"ds","key":"dir/f"}}
{"op":"assert_fingerprint","expect":{"fingerprint":"<sha256hex>"}}
```

## 4. Trace Op Catalog

### 4.1 Control ops (pool lifecycle)

| Op name | Args | Semantics |
|---|---|---|
| `trace_meta` | `schema`, `version` | Declare trace schema. Must be first op. `schema` mismatch or unsupported `version` is a hard error. |
| `create_pool` | `device_count`, `device_size_bytes`, `bootstrap_b64` | Create a fresh pool with N temp-file devices. Closes any prior pool, resets cost base. Returns `pool_id`. |
| `open_pool` | (none) | Open existing pool from device paths. |
| `restart_pool` | (none) | Alias for `open_pool`. Close + reopen pool. Cost counters persist across restarts. |
| `close_pool` | (none) | Close pool, persist cost counters. |
| `assert_fingerprint` | `expect.fingerprint` | Assert current pool state fingerprint matches expected value. Raises `AssertionError` on mismatch. |

### 4.2 Namespace ops

| Op name | Args | Semantics |
|---|---|---|
| `create_dataset` | `name` | Create a named dataset. Returns `dataset_id`. |
| `mkdir` | `dataset`, `path` | Create directory. Returns `inode_id`. |
| `create_file` | `dataset`, `path` | Create regular file. Returns `inode_id`. |
| `unlink` | `dataset`, `path` | Remove file or empty directory. |
| `rename` | `dataset`, `src`, `dst` | Rename/move within dataset. |
| `reflink` | `dataset`, `src`, `dst` | Copy-on-write reflink within dataset. |
| `lookup` | `dataset`, `path` | Look up path, return `inode_id`. |

### 4.3 File data ops

| Op name | Args | Semantics |
|---|---|---|
| `put` | `dataset`, `key`, `value_b64` | Write full file content. |
| `get` | `dataset`, `key`, `expect.value_b64` | Read full file content. Assert if `expect` present. Returns `value_b64`. |
| `write_range` | `dataset`, `key`, `offset`, `data_b64` | Write byte range into file. |
| `get_range` | `dataset`, `key`, `offset`, `length`, `expect.value_b64` | Read byte range. Assert if `expect` present. Returns `value_b64`. |

### 4.4 Snapshot ops

| Op name | Args | Semantics |
|---|---|---|
| `create_snapshot` | `dataset`, `name` | Create named snapshot of dataset. |
| `destroy_snapshot` | `dataset`, `name` | Destroy named snapshot. |

### 4.5 Directory/introspection ops

| Op name | Args | Semantics |
|---|---|---|
| `readdir` | `dataset`, `path`, `start_after?`, `max_entries?` | List directory entries. Returns `names`, `next_after`. |
| `walk` | `dataset`, `path`, `start_after?`, `max_entries?` | Walk directory tree. Returns `paths`, `next_after`. |
| `stat` | `dataset`, `path` | Stat single path. Returns stat dict. |
| `stat_batch` | `dataset`, `dir_path`, `names` | Bulk stat within directory. Returns `stats`. |

### 4.6 Maintenance ops

| Op name | Args | Semantics |
|---|---|---|
| `service_background` | `max_tasks?` | Run background maintenance (commit_group commit, reclaim). Default max_tasks=8. |

### 4.7 Wire-stable op name registry

These op name strings are the cross-implementation contract. The Rust
implementation MUST use these exact strings for trace reading and writing:

```
Control:     trace_meta, create_pool, open_pool, restart_pool, close_pool,
             assert_fingerprint
Namespace:   create_dataset, mkdir, create_file, unlink, rename, reflink,
             lookup
Data:        put, get, write_range, get_range
Snapshot:    create_snapshot, destroy_snapshot
Dir:         readdir, walk, stat, stat_batch
Maintenance: service_background
```

## 5. TraceRunner Design

### 5.1 Lifecycle

```
TraceRunner::new(workdir: &Path) -> TraceRunner

1. Creates tempdir-backed workdir for device files.
2. Initializes empty pool reference and zero cost base.

TraceRunner::run_trace(&mut self, trace_path: &Path) -> Vec<TraceEvent>

1. Load JSONL lines from file (skip comments and blanks).
3. For each op:
   a. Snapshot cost counters before execution.
   b. Dispatch op to pool or control handler.
   c. Snapshot cost counters after execution.
   d. Compute per-step cost delta.
   e. Compute pool state fingerprint.
   f. Emit TraceEvent { step, op, cost, fingerprint, result }.
4. Close pool on completion/failure.
```

### 5.2 Cost delta tracking

Cost counters track IO activity per step:

```
CostBaseline {
    read_ops: u64,
    write_ops: u64,
    flush_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
}
```

The runner maintains a cumulative `cost_base` that accumulates across
`restart_pool` and `close_pool` boundaries, so per-step deltas never go
negative across restarts:

```
_snapshot_cost() -> CostBaseline
    if pool is None: return cost_base alone
    else: return cost_base + pool.current_cost_snapshot()

_delta_cost(before, after) -> CostBaseline
    return {k: after[k] - before[k] for k in keys}
```

Cost deltas are emitted in each `TraceEvent` and can be compared against
golden trace expectations to detect IO regression.

### 5.3 Deterministic fingerprinting

After each op, the runner computes a deterministic logical state fingerprint
of the current committed state:

```
state_fingerprint() -> String  // hex-encoded BLAKE3-256
```

The fingerprint covers:

- All committed dataset inode tables (canonical sorted walk).
- All committed data content (canonical sorted walk by inode).
- Snapshot catalog entries.
- Superblock metadata.

The fingerprint algorithm must be deterministic:

- Canonical key ordering.
- Identical encoding rules across implementations.
- No timestamps, PIDs, or host-dependent values.
- No non-deterministic backend state (pool_id may vary, so fingerprint
  excludes it).

`assert_fingerprint` op compares the live fingerprint against the expected
value in the trace.

### 5.4 TraceEvent record

```
TraceEvent {
    step: u64,             // zero-based op index
    op: String,            // op name string
    cost: CostBaseline,    // per-step IO cost delta
    fingerprint: Option<String>,  // hex BLAKE3-256, None if pool closed
    result: Option<serde_json::Value>,  // op return value
}
```

### 5.5 JsonlTraceWriter

Streaming writer for deterministic trace emission from scenario suites:

```
JsonlTraceWriter::new(path: &Path) -> JsonlTraceWriter
    Creates parent directories, opens file with BufWriter.

write_op(&mut self, op: &serde_json::Value)
    Serializes with sorted keys, compact separators, writes line + flush.

close(&mut self)
    Flushes and closes file.
```

The writer is `Drop`-safe: close is called on drop if not already closed.

## 6. Golden Trace Corpus

### 6.1 Manifest format

`traces/MANIFEST.json` records every trace in the corpus:

```json
{
  "manifest_version": 1,
  "generated_by": "tidefs-trace-oracle v0.1",
  "items": [
    {
      "id": "smoke_churn_pool",
      "description": "smoke suite churn scenario (pool trace)",
      "kind": "pool",
      "path": "traces/golden/smoke_churn/pool_trace.jsonl",
      "schema": "pool_trace_v1",
      "sha256": "<hex>",
      "expected_fingerprint": "<hex>"
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier; used in test output and errors. |
| `description` | string | Human-readable scenario summary. |
| `kind` | string | `pool` or `cluster`. |
| `path` | string | Path relative to repo root. |
| `schema` | string | Trace schema identifier (`pool_trace_v1`). |
| `sha256` | string | SHA-256 of the trace file content. |
| `expected_fingerprint` | string | Hex-encoded final state fingerprint. |

### 6.2 Corpus layout

```
traces/
  MANIFEST.json              # corpus manifest
  golden/
    smoke_churn/
      pool_trace.jsonl        # create to write to read to snapshot to verify
      cluster_trace.jsonl     # (deferred)
    smoke_storm/
      pool_trace.jsonl
      cluster_trace.jsonl     # (deferred)
    crash_injection/          # future: fault-injected trace families
    snapshot_rollback/
    reflink_clone/
```

Each scenario directory contains at minimum a `pool_trace.jsonl`. Cluster
traces are deferred until the distributed runtime exists.

### 6.3 verify-trace-corpus gate

The xtask subcommand `verify-trace-corpus` replays all traces in the manifest:

```
$ tidefs-xtask verify-trace-corpus

1. Load traces/MANIFEST.json.
2. For each entry:
   a. Verify sha256 of trace file matches manifest.
   b. Create TraceRunner with tempdir workdir.
   c. Replay trace through TraceRunner::run_trace().
   d. Compare final event fingerprint against manifest expected_fingerprint.
   e. Report PASS/FAIL per trace.
3. Exit non-zero if any trace fails.
```

## 7. Trace Minimization

When a trace fails, `minimize-trace` reduces it to the smallest reproducer:

### 7.1 Algorithm

**Phase 1: Binary search for minimal failing prefix.**

```
1. Load the trace's op list (excluding trace_meta).
2. Binary search [0, n) to find the shortest prefix that still fails.
3. Trim ops after the failing prefix.
```

**Phase 2: Operation simplification.**

```
For each op in the failing prefix:
  - put/write_range with value_b64 > 4 bytes: replace with 4-byte payload,
    apply all elision rules, keep if still fails.
  - device_size_bytes > 1 MiB: halve until failure disappears or minimum
    viable size reached.
  - remove I/O operations between commits that are not needed to reproduce.
```

**Phase 3: Redundant-op removal.**

```
For each op in the failing prefix:
  - Attempt to drop the op and all subsequent ops that depend only on it.
  - If the trace still fails, keep the reduced version.
  - If it passes, restore the op.
```

### 7.2 Minimized output

The minimizer produces a minimal reproducer trace at
`traces/golden/minimized/<id>.jsonl`. The original failing trace path and
its expected fingerprint are preserved in the output comment header for
post-mortem analysis.

## 8. Trace Generation

### 8.1 Deterministic scenario suites

Scenario suites produce traces as a side effect of running deterministic
tests. Each suite:

1. Creates a `TraceRunner` with a tempdir.
2. Opens a `JsonlTraceWriter` to the output path.
3. Writes `trace_meta` as the first op.
4. Executes the scenario, writing each semantic op to the writer.
5. Closes the pool and flush-closes the writer.

Suites are written in Rust and live under `crates/tidefs-trace-oracle/tests/`
or `crates/tidefs-local-filesystem/tests/trace_scenarios/`.

### 8.2 Scenario categories

| Category | Scenario count (target) | Description |
|---|---|---|
| `smoke_churn` | 1 pool + 1 cluster | Basic create/write/read/snapshot/verify lifecycle. |
| `smoke_storm` | 1 pool + 1 cluster | Heavy write+read interleaving with background service. |
| `crash_injection` | 4-8 | Fault-injected sequences: crash at commit steps, restart, verify. |
| `snapshot_rollback` | 2-4 | Multi-snapshot create, rollback, incremental verify. |
| `reflink_clone` | 2-3 | Reflink creation, CoW mutation, clone-read verification. |

### 8.3 Trace generation contract

- All random values come from a seeded PRNG (e.g., `StdRng::seed_from_u64`).
- Trace output must be byte-identical across runs with the same seed.
- No system time, PID, hostname, or environment variable dependence.
- Base64 payload generation uses a deterministic byte sequence from the PRNG.

## 9. Integration Points

### 9.1 With LocalFileSystem

The `TraceRunner` wraps `LocalFileSystem` and maps op names to method calls:

```
create_pool      -> LocalFileSystem::create()
open_pool        -> LocalFileSystem::open()
create_dataset   -> LocalFileSystem::create_dataset()
mkdir            -> LocalFileSystem::mkdir()
create_file      -> LocalFileSystem::create_file()
put              -> LocalFileSystem::write_file()
get              -> LocalFileSystem::read_file()
write_range      -> LocalFileSystem::write_range()
get_range        -> LocalFileSystem::read_range()
unlink           -> LocalFileSystem::unlink()
rename           -> LocalFileSystem::rename()
reflink          -> LocalFileSystem::reflink()
create_snapshot  -> LocalFileSystem::create_snapshot()
destroy_snapshot -> LocalFileSystem::destroy_snapshot()
lookup           -> LocalFileSystem::lookup()
readdir          -> LocalFileSystem::readdir()
walk             -> LocalFileSystem::walk()
stat             -> LocalFileSystem::stat()
stat_batch       -> LocalFileSystem::stat_batch()
service_background -> LocalFileSystem::commit_group_maintenance_tick()
```

### 9.2 With xtask

pipeline. It:

1. Runs `cargo test -p tidefs-trace-oracle` for unit tests.
2. Runs `verify-trace-corpus` against `traces/MANIFEST.json`.
3. Exits non-zero on any failure.


### 9.3 Crate placement

```
crates/tidefs-trace-oracle/
  Cargo.toml             # depends on tidefs-local-filesystem, serde_json, sha2, blake3
  src/
    lib.rs               # TraceRunner, TraceEvent, JsonlTraceWriter, load_trace, save_trace
    protocol.rs          # op name constants, schema identifiers, JSON key constants
    minimize.rs          # TraceMinimizer (phases 1-3)
    manifest.rs          # Manifest loader/verifier, verify_trace_corpus entry point
  tests/
    trace_scenarios/     # deterministic scenario suites that emit golden traces
    trace_io_tests.rs    # unit tests for load/save/roundtrip
```



```
tidefs-xtask check-trace-oracle
```

This gate verifies:

1. This document exists and contains required sections.
2. The `POOL_TRACE_SCHEMA` and op name constants are declared in the
   authoritative trace protocol module.
3. `traces/MANIFEST.json` is valid JSON with `manifest_version: 1` and at
   least one pool trace entry.
4. Every entry in `traces/MANIFEST.json` points to a trace file whose sha256
   matches the manifest.
5. The `TraceRunner` replays pool traces deterministically matching expected
   fingerprints.
6. `JsonlTraceWriter` produces byte-identical output to the Python reference
   for equivalent operations.

## 11. Non-claims (explicit boundaries)

- This is a design spec; the Rust implementation of `tidefs-trace-oracle` is
  deferred to a successor implementation issue.
- Cluster trace support (`cluster_trace_v1`) is deferred until the distributed
  runtime is implemented. Only `pool_trace_v1` is in scope.
- The golden trace corpus currently contains only the v0.102 smoke_churn and
  smoke_storm scenarios. Expanding the corpus is deferred to scenario-specific
  issues.
- The `minimize-trace` algorithm is specified at the interface level; phase 2
  and phase 3 heuristics may need tuning based on real-world failure patterns.
- Cross-implementation comparison (Rust fingerprint vs Python fingerprint) is
  deferred until both implementations produce identical fingerprints for the
  same traces.
- Integration with chaos/corruption campaigns (#1153) is deferred to a
  successor issue that wires fault-injected traces into the golden corpus.
- Integration with xfstests (#1154) is deferred; the trace oracle is a
  complementary testing surface, not a replacement.
- The CI gate (`check-trace-oracle` in `.gitea/workflows/`) is specified but
  activation is deferred until the Rust `TraceRunner` implementation exists.
- Pool creation in `TraceRunner` uses temp-file devices; production device
  backends (ublk, kernel block device) are not used in trace replay.
