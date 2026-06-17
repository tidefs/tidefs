# tidefs-trace-oracle

Deterministic trace oracle for cross-implementation semantic regression
testing. Replays JSONL trace files against the TideFS model and local runtime
backends, tracking per-step cost deltas and computing deterministic
BLAKE3-256 state fingerprints.

This is a `proof-harness` crate (per `docs/workspace-package-classification.md`),
not `product-code`. It emits test signal only and must not be cited as a
product capability claim.

## Quick Start

```text
# Run trace scenario tests (ignored by default; generates golden traces)
cargo test -p tidefs-trace-oracle -- --ignored --nocapture

# Replay a trace through the model backend
cargo test -p tidefs-trace-oracle --lib -- backend::tests

# Run protocol-level unit tests
cargo test -p tidefs-trace-oracle
```

## Artifact Manifests

Every trace replay or comparison run produces an artifact manifest that
records trace metadata, backend, validation tier, and claim coverage. See
[`docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md`](../../docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md)
for the schema authority.

Key distinctions:

- **Model-only evidence** (`validation_tier: "model-only"`): replayed
  through `tidefs-model-core` alone. Validates contract shape and
  deterministic model behavior. Insufficient for runtime crash claims.
- **Runtime evidence** (`validation_tier: "runtime"`): replayed through a
  mounted adapter with crash injection and recovery. Required for
  crash-safety claim closure.

## Crate Structure

| Module | Purpose |
|--------|---------|
| `lib.rs` | `TraceRunner`, `TraceEvent`, `TraceOracle`, cost baseline |
| `protocol.rs` | Wire-stable op names, trace schema constants, JSON keys |
| `backend.rs` | Model and local-runtime backends, `BackendStep`, comparison |
| `manifest.rs` | Golden corpus `MANIFEST.json` loader/verifier |
| `minimize.rs` | Failing trace minimizer (binary search, simplification) |

## Trace Protocol

The trace wire protocol is defined in `src/protocol.rs`. Trace files are
JSONL with one operation per line. The current pool trace schema is
`pool_trace_v1` at trace version `1`. Cluster traces (`cluster_trace_v1`)
are deferred.

Operations are replayed through the TideFS request contract
(`docs/REQUEST_CONTRACT.md`, `tidefs-types-vfs-core`,
`tidefs-schema-codec-vfs`). The model backend routes every operation
through `tidefs-model-core`'s `ModelFs` via the contract envelope path.

## Program Authority

- Nextgen verification plan: `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`
- Claims gate policy: `docs/CLAIMS_GATE_POLICY.md`
- Request contract: `docs/REQUEST_CONTRACT.md`
- Artifact schema: `docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md`
