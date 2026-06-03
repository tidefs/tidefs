# Semantic Op Canonical Name Registry Design

Maturity: **design-spec** for the centralized semantic op name registry that
provides a single source of truth for trace/replay/cross-implementation
determinism.

This document closes Forgejo issue #1200.

## 1. Motivation

The old tidefs design treats semantic ops as the primary stable contract:

- Traces (`pool_trace.jsonl`) record semantic ops.
- The L1/Phase-2 cluster harness replicates semantic ops.
- Downstream implementations (Python → Rust, Rust → future ports) must replay them.

Without a centralized canonical op name registry, op names scatter across the
codebase as ad-hoc string literals. This causes divergence between trace
producers and consumers, breaks cluster replication, and makes cross-implementation
testing fragile.

The Python reference (v0.262) centralizes op names in `semantic_protocol.py`
The Rust codebase currently has no equivalent — op names exist only as inline
strings in trace-oracle dispatch tables and test scaffolding.

**Principle 5 (Stable contracts are centralized):** The op name registry is the
single source of truth. Any code that emits or consumes semantic ops MUST use
these constants. This prevents drift between the Python reference trace producer,
the Rust trace consumer/replayer, the cluster harness replicator, and future
implementations.

## 2. Design Decisions

### 2.1 Crate placement

The canonical registry lives in `crates/tidefs-semantic-op-registry/`, a
`#![no_std]` crate with zero mandatory dependencies. This crate is the
authoritative home for:

- Wire-stable op name constants
- Schema version identifiers
- Op metadata (mutating, namespace-affecting, data-affecting)

**Rationale:** A standalone `no_std` crate ensures the registry can be used
heavyweight dependencies. The crate has no dependency on
`tidefs-local-filesystem`, `tidefs-trace-oracle`, or any other implementation
crate — it is a pure data module.

### 2.2 Op name convention: snake_case

All op names use **snake_case**, matching the Python reference
(`semantic_protocol.py`) and Rust community conventions.

**Rationale:** snake_case avoids case-sensitivity ambiguity across
implementations. It is the established convention in the Python reference
and requires no special escaping in JSON keys. snake_case also composes
cleanly with Rust identifier conventions when ops are referenced as module
constants.

Options rejected:
- **kebab-case:** requires quoting in Rust identifiers, inconsistent with
  Python reference.
- **PascalCase / SCREAMING_SNAKE_CASE:** not used in Python reference, would
  break wire compatibility with existing trace corpus.

### 2.3 Versioned semantics

Op names are **wire-stable**. Renaming an op is a breaking change that requires
a pool trace schema version bump (e.g., `pool_trace_v2`).

Semantics are versioned at the **schema level**, not per-op:

- `pool_trace_v1` defines the full set of ops and their semantics.
- A future `pool_trace_v2` may add, remove, or change op semantics.
- The registry exposes a `supported_schema_versions()` function.

**Rationale:** Per-op versioning adds combinatorial complexity without
practical benefit. Traces are versioned as atomic schema documents. If `mkdir`
behavior changes, the entire trace is `pool_trace_v2`, and the registry maps
schema → op set.

**Backward compatibility:** Old traces (`pool_trace_v1`) continue to replay
against `pool_trace_v1` semantics. The registry retains all supported schema
versions.

### 2.4 Compile-time only (no runtime extensibility)

The registry is **compile-time only**. New ops require:

1. Adding the op name constant to the registry crate.
2. Adding the op metadata entry.
3. Adding the op to the schema-specific op set.
4. Updating all consumers (trace oracle dispatch, cluster harness, etc.).

**Rationale:** Runtime extensibility (plugin ops) would break determinism,
wire stability, and cross-implementation trace replay. Compile-time
registration ensures every implementation has the same op surface.

**Exception path:** If a future use case requires extensibility, it should
use an explicit namespace prefix (e.g., `ext:myorg.myop`) in a separate
schema version. Out of scope for `pool_trace_v1`.

### 2.5 Op metadata

The registry includes per-op metadata for the background service framework
and other consumers:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticOpMeta {
    pub name: &'static str,
    pub is_mutating: bool,
    pub affects_namespace: bool,
    pub affects_data: bool,
}
```

**Rationale:** Consumers like the background service scheduler (#1179) need to
know whether an op is mutating (write budgets), affects namespace (directory
Embedding metadata in the registry avoids duplicating classification logic.

## 3. Op Catalog (pool_trace_v1)

### 3.1 Control ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `trace_meta` | no | no | no |
| `create_pool` | yes | no | no |
| `open_pool` | no | no | no |
| `restart_pool` | no | no | no |
| `close_pool` | yes | no | no |
| `assert_fingerprint` | no | no | no |

### 3.2 Dataset/namespace ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `create_dataset` | yes | yes | no |
| `mkdir` | yes | yes | no |
| `create_file` | yes | yes | no |
| `unlink` | yes | yes | no |
| `rename` | yes | yes | no |
| `lookup` | no | no | no |

### 3.3 Data ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `put` | yes | no | yes |
| `get` | no | no | yes |
| `write_range` | yes | no | yes |
| `get_range` | no | no | yes |

### 3.4 CoW/snapshot ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `reflink` | yes | yes | no |
| `create_snapshot` | yes | yes | no |
| `destroy_snapshot` | yes | yes | no |

### 3.5 Directory/introspection ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `readdir` | no | no | no |
| `walk` | no | no | no |
| `stat` | no | no | no |
| `stat_batch` | no | no | no |

### 3.6 Maintenance ops

| Op name | is_mutating | affects_ns | affects_data |
|---------|:-----------:|:----------:|:------------:|
| `service_background` | yes | no | no |

## 4. Crate API

### 4.1 Op name constants

```rust
pub const OP_TRACE_META: &str = "trace_meta";
pub const OP_CREATE_POOL: &str = "create_pool";
pub const OP_OPEN_POOL: &str = "open_pool";
pub const OP_RESTART_POOL: &str = "restart_pool";
pub const OP_CLOSE_POOL: &str = "close_pool";
pub const OP_ASSERT_FINGERPRINT: &str = "assert_fingerprint";
pub const OP_CREATE_DATASET: &str = "create_dataset";
pub const OP_MKDIR: &str = "mkdir";
pub const OP_CREATE_FILE: &str = "create_file";
pub const OP_UNLINK: &str = "unlink";
pub const OP_RENAME: &str = "rename";
pub const OP_LOOKUP: &str = "lookup";
pub const OP_PUT: &str = "put";
pub const OP_GET: &str = "get";
pub const OP_WRITE_RANGE: &str = "write_range";
pub const OP_GET_RANGE: &str = "get_range";
pub const OP_REFLINK: &str = "reflink";
pub const OP_CREATE_SNAPSHOT: &str = "create_snapshot";
pub const OP_DESTROY_SNAPSHOT: &str = "destroy_snapshot";
pub const OP_READDIR: &str = "readdir";
pub const OP_WALK: &str = "walk";
pub const OP_STAT: &str = "stat";
pub const OP_STAT_BATCH: &str = "stat_batch";
pub const OP_SERVICE_BACKGROUND: &str = "service_background";
```

### 4.2 Schema identifiers

```rust
pub const POOL_TRACE_SCHEMA_V1: &str = "pool_trace_v1";
pub const CLUSTER_TRACE_SCHEMA_V1: &str = "cluster_trace_v1";

pub fn supported_schema_versions() -> &'static [&'static str];
```

### 4.3 Metadata access

```rust
pub fn op_meta(op_name: &str) -> Option<SemanticOpMeta>;
pub fn all_pool_ops_v1() -> &'static [SemanticOpMeta];
pub fn is_known_pool_op_v1(op_name: &str) -> bool;
```

### 4.4 Classification helpers

```rust
pub fn is_mutating(op_name: &str) -> bool;
pub fn affects_namespace(op_name: &str) -> bool;
pub fn affects_data(op_name: &str) -> bool;
```

## 5. Integration Points

### 5.1 With tidefs-trace-oracle (#1174)

The `protocol.rs` module imports op name constants from
`tidefs-semantic-op-registry` instead of defining inline strings. The trace

### 5.2 With cluster simnet (#1175)

The cluster harness uses `is_mutating()` to classify ops for replication:
mutating ops replicate; read-only ops do not.

### 5.3 With directory change streams (#1173)

Only ops with `affects_namespace: true` generate directory change notifications.

### 5.4 With background service framework (#1179)

The scheduler uses `is_mutating` for write budgets and `affects_data` for
integrity verification scheduling.

## 6. Crate Structure

```
crates/tidefs-semantic-op-registry/
  Cargo.toml
  src/
    lib.rs          # re-exports, documentation
    constants.rs    # op name constants, schema identifiers
    metadata.rs     # SemanticOpMeta struct, op metadata tables
    schema.rs       # schema version support, all_pool_ops_v1()
    helpers.rs      # classification helpers
```


```
cargo check -p tidefs-semantic-op-registry
```

A successor xtask gate (`tidefs-xtask check-semantic-op-registry`) verifies:

1. This document exists and contains required sections.
2. No duplicate op name constants.
3. Every op in the DETERMINISTIC_TRACE_ORACLE_DESIGN.md catalog has a constant.
4. `supported_schema_versions()` returns at least `pool_trace_v1`.

## 8. Non-claims

- Full Rust implementation deferred to successor issue.
- `cluster_trace_v1` deferred until distributed runtime exists.
- Runtime extensibility (plugin ops) out of scope for `pool_trace_v1`.
- xtask `check-semantic-op-registry` deferred until registry impl exists.
- Migration of inline strings in `tidefs-trace-oracle` deferred to impl issue.
- Serialization format for op metadata handled by trace format spec (#1174).
