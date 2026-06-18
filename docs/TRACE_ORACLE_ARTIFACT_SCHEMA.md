# Trace Oracle Artifact Schema

Maturity: current schema authority for trace-oracle output artifacts.

This document defines the artifact manifest schema for `tidefs-trace-oracle`
outputs. Every trace replay or comparison run produces an artifact manifest
that records what was replayed, which backend produced the result, which
validation tier the evidence belongs to, and which claim ids the result
covers. The manifest makes trace artifacts reviewable before they feed claims.

This is a schema and documentation slice. It does not add a second trace
runner or change the model replay semantics owned by issue #509.

## Authority

- Crate: `crates/tidefs-trace-oracle`
- Wire protocol: `crates/tidefs-trace-oracle/src/protocol.rs` (trace op names,
  `POOL_TRACE_SCHEMA`, `TRACE_VERSION`)
- Golden corpus manifest: `crates/tidefs-trace-oracle/src/manifest.rs`
  (`traces/MANIFEST.json` loader/verifier)
- Minimized reproducer sidecar: `crates/tidefs-trace-oracle/src/minimize.rs`
  (`MinimizedManifestEntry`)
- Request contract: `docs/REQUEST_CONTRACT.md`, `tidefs-types-vfs-core`,
  `tidefs-schema-codec-vfs` (contract version 1)
- Validation tier vocabulary:
  `crates/tidefs-validation/src/validation_schema.rs` (`ValidationTier`)
- Program authority: `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`
- Claims gate: `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`
- Workspace classification: `docs/workspace-package-classification.md`
  (trace-oracle is `proof-harness`, not `product-code`)

## Artifact Manifest Schema (v1)

Each trace-oracle artifact carries a JSON manifest file. The file is named
`<artifact-id>.manifest.json` and lives alongside the trace artifact output
(the JSONL trace file, comparison report, or minimized reproducer).

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `artifact_schema_version` | `u64` | This manifest schema version (`1`) |
| `trace_schema` | `string` | Trace protocol schema (`pool_trace_v1` or `cluster_trace_v1`) |
| `trace_version` | `u64` | Trace format version from the wire protocol (`1`) |
| `request_contract_version` | `u64` | Request contract version used (`1`) |
| `backend` | `string` | Execution backend: `model`, `local_runtime`, or `compare` |
| `environment_model` | `string` | Environment model dependency (`tidefs-model-core` for model-only) |
| `validation_tier` | `string` | Canonical `ValidationTier` label such as `source-model`, `harness-only`, `mounted-userspace`, or `mounted-kernel-vfs` |
| `evidence_class` | `string` | Claim boundary class: `model-only`, `harness-only`, or `runtime` |
| `generated_at` | `string` | ISO 8601 UTC timestamp of artifact generation |
| `generated_by` | `string` | Tool and version that produced the artifact |

### Input Descriptor

| Field | Type | Description |
|-------|------|-------------|
| `input.trace_path` | `string` | Path to the input trace file (relative to repo root or artifact root) |
| `input.trace_digest_sha256` | `string` | SHA-256 hex digest of the input trace file |
| `input.trace_op_count` | `u64` | Number of operations in the input trace (including meta) |
| `input.trace_descriptor` | `string` | Human-readable trace identifier (e.g. `smoke_churn_v1`) |

### Output Descriptor

| Field | Type | Description |
|-------|------|-------------|
| `output.events_digest_sha256` | `string` | SHA-256 hex digest of the output events JSONL |
| `output.final_fingerprint` | `string` | Final BLAKE3-256 state fingerprint after replay |
| `output.event_count` | `u64` | Number of trace events emitted |
| `output.mismatches` | `u64` | Semantic mismatch count (non-zero only for `compare` backend) |
| `output.result` | `string` | `pass`, `fail`, or `skipped` |

### Claims and Evidence

| Field | Type | Description |
|-------|------|-------------|
| `claims_covered` | `[string]` | Claim ids from `validation/claims.toml` that this artifact covers |
| `ci_artifact_ref` | `string\|null` | GitHub Actions artifact reference (null for model-only local artifacts) |
| `ci_run_url` | `string\|null` | GitHub Actions run URL (null for local artifacts) |
| `notes` | `string` | Human-readable context, limitations, or evidence-tier caveats |

### Complete Schema (JSON)

```json
{
  "artifact_schema_version": 1,
  "trace_schema": "<pool_trace_v1 | cluster_trace_v1>",
  "trace_version": 1,
  "request_contract_version": 1,
  "backend": "<model | local_runtime | compare>",
  "environment_model": "<tidefs-model-core | none | runtime>",
  "validation_tier": "<canonical ValidationTier label>",
  "evidence_class": "<model-only | harness-only | runtime>",
  "generated_at": "<ISO 8601 UTC>",
  "generated_by": "<tool-and-version>",
  "input": {
    "trace_path": "<relative-path>",
    "trace_digest_sha256": "<hex>",
    "trace_op_count": 0,
    "trace_descriptor": "<id>"
  },
  "output": {
    "events_digest_sha256": "<hex>",
    "final_fingerprint": "<blake3-hex>",
    "event_count": 0,
    "mismatches": 0,
    "result": "<pass | fail | skipped>"
  },
  "claims_covered": ["<claim-id>"],
  "ci_artifact_ref": null,
  "ci_run_url": null,
  "notes": "<context>"
}
```

## Model-Only vs Runtime Trace Evidence

The manifest records two related boundaries:

- `validation_tier` uses the canonical `ValidationTier` label from
  `crates/tidefs-validation/src/validation_schema.rs`.
- `evidence_class` records the claim-review boundary between model-only,
  harness-only, and runtime evidence.

The model/runtime distinction is program law from
`docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md` and
`docs/CLAIMS_GATE_POLICY.md`.

### Model-Only Evidence (`evidence_class: "model-only"`)

- The trace was replayed through `tidefs-model-core` (`ModelFs`) without a
  mounted filesystem, kernel interaction, FUSE adapter, or real storage
  device.
- Validation tier is normally `source-model`.
- Backend is `model` or `compare` where one side is the model backend.
- The environment model is `tidefs-model-core`, which is a deterministic
  in-process simulation of TideFS contract semantics.
- Model-only evidence may diagnose contract shape, request routing, and
  deterministic model behavior.
- **Model-only evidence must not validate runtime crash claims.** Crash
  safety, rename atomicity across crashes, flush durability, and recovery
  correctness require a mounted runtime backend with actual crash injection
  and recovery cycles.

### Harness-Only Evidence (`evidence_class: "harness-only"`)

- The trace was replayed through a local userspace harness (FUSE or uBLK)
  that exercises the real storage stack but without crash injection.
- Validation tier is normally `harness-only`.
- Backend is `local_runtime` or `compare` where one side is the local
  runtime backend.
- Harness-only evidence may diagnose adapter translation, basic I/O
  correctness, and performance baseline.
- Harness-only evidence without crash injection is **not runtime crash
  evidence**.

### Runtime Evidence (`evidence_class: "runtime"`)

- The trace was replayed through a mounted adapter with crash injection
  and recovery, or through a kernel-resident path with controlled fault
  injection.
- Validation tier must be one of the canonical runtime tiers such as
  `mounted-userspace`, `qemu-guest`, `mounted-kernel-vfs`,
  `kernel-block-io`, `full-kernel-no-daemon`, or
  `multi-process-distributed`.
- Runtime evidence requires a `ci_artifact_ref` pointing to a GitHub
  Actions artifact that contains the runtime trace output, crash log, and
  recovery log.
- Only runtime evidence with the required crash/recovery class may close
  crash-safety claims in `validation/claims.toml`.

## Example: Model-Only Trace Artifact Manifest

This manifest describes a model-only trace replay that exercises deterministic
pool operations through `ModelFs`. It is useful for contract-shape diagnosis
but **insufficient for runtime crash claims**.

```json
{
  "artifact_schema_version": 1,
  "trace_schema": "pool_trace_v1",
  "trace_version": 1,
  "request_contract_version": 1,
  "backend": "model",
  "environment_model": "tidefs-model-core",
  "validation_tier": "source-model",
  "evidence_class": "model-only",
  "generated_at": "2026-06-18T00:30:00Z",
  "generated_by": "tidefs-trace-oracle 0.1.0",
  "input": {
    "trace_path": "traces/golden/smoke_churn/pool_trace.jsonl",
    "trace_digest_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "trace_op_count": 15,
    "trace_descriptor": "smoke_churn_v1"
  },
  "output": {
    "events_digest_sha256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "final_fingerprint": "6b23c0d5f35d1b11f9b683f0b1a5e7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
    "event_count": 15,
    "mismatches": 0,
    "result": "pass"
  },
  "claims_covered": ["trace.model.replay.v1"],
  "ci_artifact_ref": null,
  "ci_run_url": null,
  "notes": "Model-only trace artifact. Validates deterministic contract replay through ModelFs. Insufficient for runtime crash claims. Runtime crash evidence requires a mounted backend with crash injection and recovery, plus a ci_artifact_ref to the GitHub Actions run artifact."
}
```

## Runtime Trace GitHub Actions Artifact References

When a trace is replayed through a mounted runtime backend in CI, the
artifact manifest records the GitHub Actions artifact path without embedding
secrets or private runner state.

### Rules

1. `ci_artifact_ref` must be a public GitHub Actions artifact name as it
   appears in the run's artifact list (e.g. `trace-compare-smoke-churn-42`).
   It must not contain runner hostnames, internal IP addresses, internal
   filesystem paths outside the workspace, TLS keys, access tokens, or
   repository secret values.

2. `ci_run_url` must be the public URL of the GitHub Actions workflow run
   (e.g. `https://github.com/tidefs/tidefs/actions/runs/1234567890`). It
   must not point to internal runner dashboards or private infrastructure.

3. The artifact manifest file itself must be stored in the repository or
   attached as a reviewable CI artifact. It must never contain secret
   material.

4. The trace output file (JSONL) referenced by the manifest may also be
   stored as a CI artifact. Its digest in the manifest ties the reviewable
   manifest to the specific artifact bytes.

### Example: Runtime Trace Artifact Manifest

```json
{
  "artifact_schema_version": 1,
  "trace_schema": "pool_trace_v1",
  "trace_version": 1,
  "request_contract_version": 1,
  "backend": "compare",
  "environment_model": "runtime",
  "validation_tier": "mounted-userspace",
  "evidence_class": "runtime",
  "generated_at": "2026-06-18T01:00:00Z",
  "generated_by": "tidefs-trace-oracle 0.1.0",
  "input": {
    "trace_path": "traces/golden/smoke_churn/pool_trace.jsonl",
    "trace_digest_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "trace_op_count": 15,
    "trace_descriptor": "smoke_churn_v1"
  },
  "output": {
    "events_digest_sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "final_fingerprint": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
    "event_count": 15,
    "mismatches": 0,
    "result": "pass"
  },
  "claims_covered": ["trace.runtime.compare.v1"],
  "ci_artifact_ref": "trace-compare-smoke-churn-42",
  "ci_run_url": "https://github.com/tidefs/tidefs/actions/runs/1234567890",
  "notes": "Runtime trace comparison artifact. Model and local-runtime backends compared through a mounted FUSE backend with crash injection and recovery logging enabled. Claim closure still requires a registered claim id and claims-gate review."
}
```

## Relationship to Existing Trace Oracle Structures

This artifact schema is a reviewable metadata wrapper, not a replacement for
any existing trace oracle structure. The existing structures remain the
authoritative trace data:

| Structure | Authority | Relationship |
|-----------|-----------|--------------|
| `traces/MANIFEST.json` | `crates/tidefs-trace-oracle/src/manifest.rs` | Golden corpus index; the artifact manifest wraps individual replay results |
| `MinimizedManifestEntry` | `crates/tidefs-trace-oracle/src/minimize.rs` | Minimized reproducer sidecar; the artifact manifest wraps the minimization session |
| `TraceOracleStats` | `crates/tidefs-trace-oracle/src/lib.rs` | In-memory replay statistics; the artifact manifest output block records the final stats |
| `BackendStep` | `crates/tidefs-trace-oracle/src/backend.rs` | Per-operation backend comparison; the artifact manifest records aggregate mismatch count |

## Validation

This schema slice requires no runtime validation. Validate through:

```text
git diff --check
```

And docs review against:

- `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`
- `docs/CLAIMS_GATE_POLICY.md`

If doc tests or schema-related tests are added to `crates/tidefs-trace-oracle`,
run (only when disk headroom permits):

```text
cargo test -p tidefs-trace-oracle
```

## Claim Coverage

This document does not close any product claim. It defines the artifact
metadata format that future model and runtime trace evidence artifacts will
use when they are recorded as claim evidence. The claim ids listed in example
manifests (`trace.model.replay.v1`, `trace.runtime.compare.v1`) are example
identifiers that must match registered claim ids in `validation/claims.toml`
before they can be cited.
