# Nextgen Verification, Performance, and Offload Program

Maturity: current program authority for issue #483.

This document integrates the next-generation verification/performance/offload
guide into the current TideFS repository. It is the program authority for the
verification spine that should grow into TideFS's ztest-successor: a
repeatable system that generates, replays, crashes, checks, budgets, and gates
TideFS behavior through machine-readable evidence.

This is not a present-tense product claim. TideFS is not formally verified, not
production ready, not POSIX complete, not kernel complete, and not
OpenZFS/Ceph-class until the claim registry and validation artifacts prove the
specific wording.

The uploaded guide at `/root/tidefs_nextgen_audited_final_guide.md` is operator
input. This repository document is the TideFS authority that maps that input to
current crates, docs, claim gates, and issue lanes.

## Core Rule

TideFS should build a next-generation ztest successor, not a second filesystem
or a pile of proof-themed scaffolding.

The program spine is:

1. canonical TideFS request and completion records;
2. deterministic executable model;
3. trace oracle and model/runtime comparison;
4. crash oracle and recovery outcome matrix;
5. performance/admission oracle;
6. no-hidden-queue registry and scanner;
7. claim registry with `validate-claim` receipts;
8. focused formal proof harnesses for small settled state machines;
9. adapter environment models for FUSE, uBLK, kernel, and distributed edges;
10. non-authoritative offload ABI and CPU reference backend.

The test harness should be aggressive, adversarial, and reusable. The product
law must remain conservative.

## Finality Rule

Only settled TideFS invariants become hard gates.

Hard gates are appropriate for rules that are already repository law, such as:

- adapters translate; engines implement;
- a request path must refine into the TideFS request contract before it can
  claim TideFS semantics;
- exact domain status must not be collapsed into a lossy generic status;
- durability-sensitive success requires a named durability boundary;
- every scarce runtime resource needs visible admission/accounting;
- queue roots must be registered or explicitly reviewed;
- lower validation tiers may diagnose but must not close higher-tier claims;
- offload results are never storage semantics authority;
- `validation/claims.toml` and `validate-claim` decide claim status;
- publishing-facing docs stay behind `docs/CLAIMS_GATE_POLICY.md`.

Unsettled design stays out of hard gates. Encode it as one of:

- a `planned` or `blocked` claim in `validation/claims.toml`;
- a model assumption with a named scope;
- a missing evidence class;
- a GitHub issue with acceptance criteria and expected write set;
- a structured allowlist entry with a reason;
- a docs-only design input that cannot be cited as runtime proof.

Do not turn future design preference into a failing CI gate until the invariant
is final enough that ordinary TideFS work should not violate it.

## Current Reusable Inventory

The nextgen program is already partially implemented. New work must reuse these
anchors instead of creating parallel systems.

Before adding any crate, trace format, artifact class, claim path, or harness,
workers must rediscover the current workspace through
`docs/workspace-package-classification.md`, root `Cargo.toml`, `crates/README.md`,
live issue/PR state, and focused `rg --files` inspection. The uploaded guide's
crate names describe desired authority roles. They are not permission to create
duplicate packages when the repository already has an authority with a different
name or a narrower scope.

| Program area | Current TideFS authority | Status and finishing direction |
| --- | --- | --- |
| Workspace inventory | `docs/workspace-package-classification.md`, root `Cargo.toml`, `crates/README.md`, `xtask check-workspace-policy` | Use this before creating or deleting packages. Package role classification is navigation and policy evidence, not product proof. |
| Integrated roadmap | `docs/NEXTGEN_VERIFICATION_CONTRACT_ROADMAP.md` from PR #299 | Keep as staging history. This document is the integrated program authority for issue #483. |
| Request contract | `docs/REQUEST_CONTRACT.md`, `crates/tidefs-types-vfs-core`, `crates/tidefs-schema-codec-vfs` from PRs #300 and #315 | Reuse these instead of adding `tidefs-contract-core` or `tidefs-contract-codec` unless a future issue proves the split is needed. |
| Contract codecs | `xtask check-contract-codecs`, fixed v1 request/completion codec, golden vectors, reserved-field rejection | Good seed for contract-shape validation. This is codec/tooling evidence, not runtime adapter proof. |
| Validation tiers | `crates/tidefs-validation/src/validation_schema.rs` | Canonical T0-T7 tier vocabulary. Do not invent another tier taxonomy. |
| Executable model | `crates/tidefs-model-core` from PR #301 | Pure in-memory model. It consumes contract envelopes for the seeded VFS ops. It remains model authority only, not runtime storage authority. |
| Trace oracle | `crates/tidefs-trace-oracle`, `traces/MANIFEST.json`, `xtask check-trace-oracle` from PR #304 | Reuse for corpus verification and model/runtime comparison. Extend it rather than adding another trace runner. |
| Claim registry | `validation/claims.toml`, `docs/CLAIM_REGISTRY.md`, `xtask validate-claim`, `xtask check-claims-gate` from PR #305 | Stable claim authority. Planned, blocked, and invalid claims fail closed. |
| Crash oracle | `crates/tidefs-crash-oracle`, `validation/artifacts/crash-oracle/*` from PR #306 and PR #333 | Current artifacts are bounded model-only evidence. Runtime crash claims remain blocked until runtime crash artifacts exist. |
| Performance contract | `crates/tidefs-performance-contract` and `validation/performance/no-hidden-queues.toml` from PR #307 | Reuse work classes, resource domains, admission permits, budgeted queues, service curves, and no-hidden-queue registry. |
| Local admission runtime | issue #308 | Local admission wiring exists, but `perf.local.no_unbounded_dirty_debt.v1` still needs runtime queue-depth artifacts before validation. |
| No-hidden queues | `xtask check-no-hidden-queues` | The checker scans touched implementation packages and registry entries. Broaden carefully as the registry matures. |
| uBLK environment model | `crates/tidefs-env-ublk-model`, `validation/artifacts/ublk/*` from PR #309 | Bounded qid/tag model evidence exists. Runtime artifacts and claims-gate review still gate stronger uBLK wording. |
| FUSE environment model | `crates/tidefs-env-fuse-model` from PR #311 | Adapter lifecycle model seed. It does not replace mounted FUSE runtime validation. |
| Kernel teardown model | `validation/artifacts/kernel/teardown-race-proof-artifact.json` from issue #291 | Bounded source-model evidence only. It is not mounted-kernel runtime proof. |
| Kernel environment seed | `crates/tidefs-kmod-posix-vfs/src/kernel_env_model.rs` plus kernel validation rows | Reuse this as the current Linux/kernel VFS model seed. Do not create `tidefs-env-linux-vfs-model` just to match guide naming unless a focused issue proves a crate split is needed. |
| Offload boundary | `crates/tidefs-offload-core`, `validation/artifacts/offload/*` from PR #324 | `offload.ready.non_authoritative.v1` is validated for descriptor, lease, completion, and CPU reference scope only. It is not GPU/FPGA/DMA/kernel/RDMA/storage-runtime evidence. |
| Distributed model | `crates/tidefs-distributed-model-check` from PRs #365 and #374 | Reuses settled placement/receipt types. Runtime distributed claims remain separate claim-gated work. |
| Verification engine | `crates/tidefs-verification-engine` | Existing object/replication verification machinery should be a consumer or artifact source, not a parallel claim authority. |
| Claim ledger types | `crates/tidefs-types-claim-ledger-core`, `crates/tidefs-claim-ledger`, `crates/tidefs-reserve-ledger` | Reuse existing ledger/value types when evidence or receipt plumbing needs them. They do not replace `validation/claims.toml` or `validate-claim` as claim authority. |
| Runtime/proof harnesses | `crates/tidefs-workload`, `crates/tidefs-two-node-harness`, `crates/tidefs-posix-guarantee-verifier`, demo apps, and `crates/tidefs-validation` smoke surfaces | Potential artifact producers and comparison consumers. Use them when they fit the issue; do not treat harness existence as release proof. |

Guide target names that do not currently exist, such as
`tidefs-property-catalog`, `tidefs-admission-governor`,
`tidefs-service-model`, and `tidefs-proof-harness`, are role names until an
issue proves a real package boundary is necessary. Prefer extending the
existing request contract, model, validation, performance, workload, and
environment-model surfaces first.

## What To Finish First

The first complete milestone is one vertical slice:

```text
write -> fsync -> read -> crash/recover
```

The slice is done only when all of the following are true:

- the trace enters through the existing request contract;
- `tidefs-model-core` can replay the sequence deterministically;
- `tidefs-trace-oracle` compares model and local runtime outcomes;
- `tidefs-crash-oracle` records the model crash matrix;
- a runtime crash artifact exists for the local filesystem path;
- no-hidden-queue and admission metadata cover the touched dirty path;
- `validate-claim local.vfs.write_fsync_crash.v1` returns `PASS` or a precise
  `BLOCKED` with named missing evidence classes;
- no publishing-facing doc claims more than the receipt allows.

Current state: `local.vfs.write_fsync_crash.v1` is blocked because model-only
crash evidence is not runtime crash evidence. That is useful. The next work
should finish the missing runtime artifact path, not create another model-only
crash matrix with a new name. Prepared follow-up issue #486 owns the first
write/fsync/read/crash-recover evidence slice. If that slice is too broad for
one PR, split it into non-overlapping issues for trace/model replay, runtime
crash artifact collection, dirty-queue evidence, and final claim-gate status
instead of letting one broad ticket monopolize the lane.

## Evidence Classes

Use existing validation tier language from
`crates/tidefs-validation/src/validation_schema.rs`.

| Evidence kind | Typical tier | What it may prove | What it must not prove |
| --- | --- | --- | --- |
| Contract shape, codec, schema, model assumption | T0 `SourceModel` or T1 `CargoUnit` | source/model/schema invariants | mounted runtime behavior |
| Pure executable model or bounded state machine | T0/T1 | expected semantics for modeled scope | product runtime correctness |
| Harness mechanics | T2 `HarnessOnly` | harness parser, runner, receipt format | product behavior without real backend |
| Mounted FUSE/local runtime artifact | T3 `MountedUserspace` or `QemuGuest` | covered mounted userspace slice | kernel/no-daemon behavior |
| Kbuild/module load | T4 | build/load viability | mounted kernel I/O semantics |
| Mounted kernel VFS or kernel block I/O | T5 | covered kernel runtime slice | full-kernel no-daemon completeness |
| Full-kernel no-daemon | T6 | covered no-daemon kernel behavior | distributed behavior |
| Multi-process distributed/RDMA | T7 | covered distributed slice | unmodeled production guarantees |

`validate-claim` must reject insufficient tiers. A lower-tier result may help
debug a claim, but it cannot close the claim.

## Formal Verification Use

Formal tools should be surgical. Do not try to prove the whole stack as one
artifact.

Use Kani, Verus, Loom/Shuttle, Miri, or TLA+/Stateright only when the target is
small and stable enough to be a real proof target:

- codec malformed-input rejection;
- exact status mapping tables;
- extent non-overlap and split/merge cores;
- admission permit conservation;
- dirty-debt threshold boundaries;
- uBLK qid/tag state transitions;
- kernel teardown token state machines;
- distributed epoch/lease/quorum/placement safety;
- offload descriptor reserved-field and generation validation.

Normal `cargo check --workspace` must not require optional formal-verification
tools. If a proof command is added before tools are available everywhere, it
must emit an honest skipped-tool receipt, not a fake pass.


## Verification Surface Survey

This survey catalogues every verification, model, trace, crash, performance,
adapter, and offload surface found in the repository as of 2026-06-22. The
survey scope is informed by `docs/workspace-package-classification.md`, root
`Cargo.toml`, live crate sources, and the claim registry at
`validation/claims.toml`.

### Model Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Deterministic VFS model | `crates/tidefs-model-core` | `proof-harness` | Pure in-memory `ModelFs` with `ModelPath`, `ModelRequest`, deterministic `ModelFingerprint`, and `ModelRunReceipt`. Accepts contract request envelopes from `tidefs-types-vfs-core`. Owns no runtime storage. |
| Distributed safety model | `crates/tidefs-distributed-model-check` | `proof-harness` | Bounded model check of membership epochs, leases, quorum writes, placement receipts, and rebuild safety invariants. Emits `DistributedSafetyReceipt` for claim coverage. |
| Replication model | `crates/tidefs-replication-model` | `product-code` | Canonical replica-set state machines (flow, chunk, durability), placement intent, and failure-domain classification. Consumed by all multi-node replication crates. |

### Trace Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Trace oracle | `crates/tidefs-trace-oracle` | `proof-harness` | JSONL trace replay against `LocalFileSystem`, model/runtime comparison, minimization, and `TraceArtifactManifest` output. Golden corpus in `traces/`. |
| Trace artifact schema | `docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md` | schema authority | Defines the artifact manifest schema v1 for trace-oracle outputs: required fields, input/output descriptors, claims coverage, and CI artifact references. |
| Trace protocol | `crates/tidefs-trace-oracle/src/protocol.rs` | wire format | Pool and cluster trace schemas (`POOL_TRACE_SCHEMA`, `CLUSTER_TRACE_SCHEMA`), op names, trace version. |
| Trace comparison backend | `crates/tidefs-trace-oracle/src/backend.rs` | comparison engine | `BackendStep`, `TraceComparison`, model vs. local-runtime comparison logic. |
| Trace minimization | `crates/tidefs-trace-oracle/src/minimize.rs` | reproducer | `MinimizedManifestEntry` sidecar for minimized trace failures. |

### Crash-Oracle Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Crash oracle (model) | `crates/tidefs-crash-oracle` | `proof-harness` | Model-first `CrashBoundary` enumeration covering intent-append through cache-evict. Produces crash matrices with `CrashClassification` outcomes. Claim ids include `storage.write_fsync.crash_safety.v1`, `namespace.rename.atomicity.v1`. |
| Crash runtime report | `crates/tidefs-crash-oracle/src/runtime_report.rs` | runtime schema | Local runtime crash report schema and verifier, distinct from model-only crash matrices. |
| Intent-log replay matrix | `crates/tidefs-crash-oracle/src/intent_log_replay_matrix.rs` | recovery matrix | Feature-gated (`intent-log-replay`) module for intent-log crash/recovery matrix generation. |
| Validation crash recovery | `crates/tidefs-validation/src/crash_recovery.rs` | validation helper | Mounted crash/recovery test helpers. |
| Local VFS runtime crash | `crates/tidefs-validation/src/local_vfs_runtime_crash_artifact.rs` | runtime artifact | Local VFS runtime crash artifact collection and verification. |
| kmod crash consistency | `crates/tidefs-validation/src/kmod_crash_consistency_e2e.rs` | kernel validation | Kernel-module end-to-end crash consistency validation. |

### Performance Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Performance contract | `crates/tidefs-performance-contract` | `product-code` | Typed `WorkClass`, `ResourceDomain`, `WriteAdmissionState`, `BudgetedQueue`, and deterministic `OracleConfig`/`OracleOutcome`. Pure accounting and oracle signal. |
| Performance gate | `crates/tidefs-validation/src/performance_gate.rs` | validation gate | Performance gate helpers for validation runs. |
| No-hidden-queues | `validation/performance/no-hidden-queues.toml` | registry | Queue registry checking configuration. |
| Performance xtask | `xtask check-no-hidden-queues` | policy tooling | Tooling gate for queue visibility enforcement. |

### Offload Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Offload core | `crates/tidefs-offload-core` | `product-code` | `OffloadDescV1`, `OffloadCompletionV1`, `BufferLeaseV1`, `CpuReferenceBackend`. Non-authoritative; CPU backend is semantic reference for future accelerators. |
| Offload validation | `crates/tidefs-offload-core` (tests) | unit validation | Inline test suite for descriptor encoding, completion validation, lease matching, and CPU reference execution. |

### Adapter Environment Model Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| FUSE env model | `crates/tidefs-env-fuse-model` | `proof-harness` | Pure FUSE connection/request lifecycle model. Translates semantic FUSE requests into TideFS request-contract envelopes, replays through `tidefs-model-core`. Model-only evidence; not runtime xfstests replacement. |
| uBLK env model | `crates/tidefs-env-ublk-model` | `proof-harness` | Bounded uBLK qid/tag lifecycle model. Records slot ownership, generates legal uBLK I/O submissions as contract envelopes, enforces exactly-once completion per request token. |

### Validation and Tier Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Validation crate | `crates/tidefs-validation` | `proof-harness` | Central userspace validation support: `ValidationTier` enum (T0-T7), `ValidationRow`, `EvidenceArtifactManifest`, crash recovery, kernel validation matrix, kernel fsync evidence, xfstests evidence, uBLK artifacts, smoke tests, and trace helpers. |
| Validation schema | `crates/tidefs-validation/src/validation_schema.rs` | schema | Canonical `ValidationTier` enum, `ValidationRow`, `ValidationBackend`. |
| Evidence artifact manifest | `crates/tidefs-validation/src/evidence_artifact_manifest.rs` | manifest | Reusable `EvidenceArtifactManifest` with `claim_id`, `evidence_class`, `validation_tier`, `content_digest`, and `blocking_issues`. |
| Validation status | `crates/tidefs-validation/src/validation_status.rs` | status | `ValidationStatus` records for pass/fail/skip/deferred outcomes. |
| Kernel validation matrix | `crates/tidefs-validation/src/kernel_validation_matrix.rs` | kernel validation | Mounted kernel VFS validation matrix helpers. |
| Kernel fsync evidence | `crates/tidefs-validation/src/kernel_fsync_evidence.rs` | kernel evidence | Kernel fsync durability evidence collection. |
| Kernel pagecache writeback | `crates/tidefs-validation/src/kernel_pagecache_writeback_validation.rs` | kernel validation | Page-cache writeback validation. |
| xfstests evidence manifest | `crates/tidefs-validation/src/xfstests_evidence_manifest.rs` | xfstests | xfstests run evidence manifest collection. |
| xfstests tiering | `crates/tidefs-validation/src/xfstests_tiering.rs` | xfstests | xfstests tiering classification. |
| uBLK completion artifact | `crates/tidefs-validation/src/ublk_completion_artifact.rs` | uBLK | uBLK completion validation artifact. |
| uBLK started export | `crates/tidefs-validation/src/ublk_started_export_admission_artifact.rs` | uBLK | uBLK export admission artifact. |
| Two-node harness | `crates/tidefs-two-node-harness` | `proof-harness` | Deterministic two-node transport harness for distributed validation: identity exchange, BLAKE3-authenticated messages, chunk shipping, deterministic teardown. |
| FUSE integrity (two-node) | `crates/tidefs-validation/src/two_node_harness_fuse_integrity.rs` | harness test | Two-node harness FUSE integrity validation. |

### Claim and Evidence Aggregation Surfaces

| Surface | Crate / Path | Role | Description |
| --- | --- | --- | --- |
| Claim registry | `validation/claims.toml` | registry authority | Registry of claim ids, statuses, required evidence classes, blockers, and generated documentation. |
| Claim ledger | `crates/tidefs-claim-ledger` | `policy-tooling` | Policy-tooling surface for claim management. |
| Claims gate policy | `docs/CLAIMS_GATE_POLICY.md` | policy guardrail | Publishing-facing capability wording enforcement via `xtask check-claims-gate`. |
| Claims gate xtask | `xtask check-claims-gate`, `xtask validate-claim` | policy tooling | Enforceable CI gate and per-claim validation. |
| Contract codec xtask | `xtask check-contract-codecs` | policy tooling | Golden-vector contract codec validation. |
| Workspace policy xtask | `xtask check-workspace-policy` | policy tooling | Package role classification enforcement. |

## Evidence-Chain Model

TFR-021 records that the verification spine needs one evidence chain instead of
separate request-contract, model, trace, crash, performance, adapter, and
offload systems. This section compares two evidence-chain models and records
the chosen design.

### Model A: Unified Evidence Manifest with Typed Claim Anchors (chosen)

All evidence artifacts carry a typed manifest that records the claim id,
evidence class, validation tier, source crate, artifact content digest, and
blocking issues. The central claims registry (`validation/claims.toml`)
defines which evidence classes are required for each claim. The claims-gate
tooling (`xtask check-claims-gate`, `xtask validate-claim`) validates that
all required evidence classes exist with matching artifacts.

Evidence flow:

```
Model / Trace / Crash / Performance / Adapter / Offload
             |
             v
     Evidence Artifact (JSON/TOML/JSONL + manifest)
             |
             v
    claims.toml registry (required evidence classes)
             |
             v
    xtask check-claims-gate / validate-claim
             |
             v
    docs/CLAIM_REGISTRY.md (generated, CI-enforced)
```

Benefits:

- Single evidence manifest schema (`EvidenceArtifactManifest` for
  claim support, `TraceArtifactManifest` for trace-oracle outputs).
- Machine-checkable claim closure: `validate-claim` rejects claims with
  missing evidence classes or stale artifacts.
- Consistent evidence-class vocabulary across model, runtime, and
  distributed artifacts.
- No manual assembly step between evidence generation and claim validation.

Drawbacks:

- All evidence producers must adopt the manifest format (though the schema
  is intentionally minimal and crate-agnostic).
- Central claims registry requires deliberate update discipline; registry
  drift without evidence is caught by `check-claims-gate`.

### Model B: Per-System Artifact Bundles with Manual Assembly (rejected)

Each verification system produces its own artifact format (crash matrices in
one JSON shape, trace artifacts in another, performance outcomes in TOML,
adapter model evidence in yet another). A human reviewer assembles these into
a claim review document that states whether the claim is satisfied.

Benefits:

- Each system is independently evolvable without a shared manifest contract.
- No central registry bottleneck.

Drawbacks (why rejected):

- No automated evidence-chain validation; manual assembly is error-prone.
- Impossibility of machine-checking that all required evidence classes exist
  for a claim.
- Evidence fragmentation makes it hard to see verification coverage gaps
  across the program.
- This is the pre-existing scattered approach that TFR-021 identifies as a
  problem.

### Chosen Model and Binding Detail

Model A is chosen. The unified evidence chain is the program authority,
enforced through the claims-gate tooling. The following bindings define how
each verification domain feeds into the chain:

**Model-to-trace binding.** `tidefs-model-core` produces deterministic
`ModelFingerprint` values from contract request envelopes.
`tidefs-trace-oracle` replays model-generated or captured traces and compares
model fingerprints against local-runtime fingerprints. The binding is through
`tidefs-types-vfs-core` request envelopes and `ModelFingerprint` (BLAKE3-256).
The trace oracle records comparison outcomes in `TraceArtifactManifest`
entries with `evidence_class: "model-only"` or `"harness-only"`.

**Trace-oracle artifact schema.** Defined in
`docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md` and implemented in
`crates/tidefs-trace-oracle/src/artifact_manifest.rs`. Every trace replay or
comparison produces a `TraceArtifactManifest` recording input digest, output
fingerprint, mismatches, backend, validation tier, evidence class, and claim
coverage. The manifest distinguishes model-only evidence (insufficient for
runtime crash claims) from runtime evidence (requires CI artifact reference).

**Crash-oracle integration.** `tidefs-crash-oracle` produces model crash
matrices (`CrashBoundary` times `CrashClassification`) and runtime crash reports.
Model matrices are `source-model` evidence for `model-crash-matrix` classes.
Runtime crash reports from mounted backends produce `mounted-userspace`
evidence for `runtime-crash-oracle` classes. The crash-oracle's claim ids
(e.g. `local.vfs.write_fsync_crash.v1`) map to `validation/claims.toml`
entries that name their required evidence classes.

**Performance-contract binding.** `tidefs-performance-contract` provides
deterministic `OracleOutcome` values from `OracleConfig` inputs, proving
that admission and scheduling protect foreground work under bounded
background pressure. Performance oracle outcomes are `harness-only` evidence
for `admission-budget` or `isolation-model` evidence classes. Runtime
performance claims (queue-depth, dirty-debt caps) require `mounted-userspace`
or higher-tier artifacts. The `no-hidden-queues` registry and
`xtask check-no-hidden-queues` gate provide queue-visibility evidence
independent of oracle outcomes.

**Adapter model evidence.** `tidefs-env-fuse-model` and
`tidefs-env-ublk-model` produce model-only evidence that adapter request
translation is legal: FUSE operations refine into TideFS request-contract
envelopes without semantic distortion, and uBLK qid/tag slots enforce
exactly-once completion per request token. This evidence is `source-model`
tier and feeds into `claims-gate-review` classes. Adapter models do not
validate mounted runtime behavior.

**Offload staging.** `tidefs-offload-core` provides the `offload.ready.
non_authoritative.v1` claim with descriptor validation, buffer lease matching,
completion validation, and CPU reference kernels. Offload evidence is
`harness-only` at the descriptor/lease/completion level; future accelerator
conformance (GPU, FPGA, DMA, RDMA) requires the same evidence classes as the
CPU reference path plus accelerator-specific validation artifacts.
Offload results are performance mechanism evidence only and must never be
treated as storage semantics authority.

## Evidence Producer and Consumer Map

### Primary Evidence Producers

These crates are the canonical evidence sources. Each produces artifacts with
typed manifests that feed the claims registry.

| Producer crate | Role | Evidence produced | Manifest type | Validation tier |
| --- | --- | --- | --- | --- |
| `tidefs-model-core` | `proof-harness` | `ModelRunReceipt`, deterministic fingerprint | `ModelRunReceipt` (JSON) | `source-model` |
| `tidefs-trace-oracle` | `proof-harness` | Trace replay/comparison artifacts | `TraceArtifactManifest` | `source-model` or `harness-only` |
| `tidefs-crash-oracle` | `proof-harness` | Crash matrices, runtime crash reports | `EvidenceArtifactManifest` | `source-model` or `mounted-userspace` |
| `tidefs-performance-contract` | `product-code` | Admission/oracle outcomes | `EvidenceArtifactManifest` | `harness-only` |
| `tidefs-offload-core` | `product-code` | Descriptor/completion/lease validation, CPU reference results | `EvidenceArtifactManifest` | `harness-only` |
| `tidefs-env-fuse-model` | `proof-harness` | FUSE adapter-to-contract refinement evidence | `EvidenceArtifactManifest` | `source-model` |
| `tidefs-env-ublk-model` | `proof-harness` | uBLK qid/tag lifecycle evidence | `EvidenceArtifactManifest` | `source-model` |
| `tidefs-distributed-model-check` | `proof-harness` | `DistributedSafetyReceipt` | `EvidenceArtifactManifest` | `source-model` |
| `tidefs-two-node-harness` | `proof-harness` | Two-node transport determinism evidence | `EvidenceArtifactManifest` | `harness-only` |
| `tidefs-validation` | `proof-harness` | Mounted runtime artifacts (kernel VFS, FUSE, uBLK, xfstests) | `EvidenceArtifactManifest` | `mounted-userspace` through `multi-process-distributed` |

### Primary Evidence Consumers and Aggregators

These crates and tools consume evidence artifacts and aggregate them into
claim validation outcomes.

| Consumer | Role | Consumes | Output |
| --- | --- | --- | --- |
| `validation/claims.toml` | registry authority | Evidence manifest references | Claim status, required evidence classes |
| `tidefs-claim-ledger` | `policy-tooling` | Evidence manifests | Claim ledger records |
| `xtask check-claims-gate` | policy tooling | Claims registry + evidence manifests | CI pass/fail, drift detection |
| `xtask validate-claim <id>` | policy tooling | Claims registry + single claim evidence | Per-claim validation receipt |
| `docs/CLAIM_REGISTRY.md` | generated doc | Claims registry (generated) | Human-readable claim status |
| `docs/CLAIMS_GATE_POLICY.md` | policy guardrail | All of the above | Publishing-facing wording enforcement |
| `tidefs-validation::evidence_artifact_manifest` | validation helper | Evidence manifest files | Manifest validation |

## Adapter Boundary

Adapters may decode external protocols, validate external shape, map external
IDs, classify work, acquire admission, call the contract dispatch path, map
exact completions back to external status, emit traces, and manage external
lifecycle tokens.

Adapters must not update object storage directly, publish roots, own allocator
truth, decide durability policy, invent namespace semantics, repair corruption,
bypass admission for ordinary work, silently drop unsupported operations, or
claim external runtime proof from a model-only artifact.

## Performance As Correctness

Performance work in this program is not benchmark folklore. A performance
claim requires a workload envelope, environment profile, comparator or baseline
policy, measurement vector, budget decision, and receipt.

The first hard performance shape is visibility:

- dirty bytes and dirty operations must be admitted;
- queues must be registered;
- foreground and background work classes must not share hidden capacity;
- fsync/flush/FUA paths must retain forward progress under ordinary pressure;
- no runtime path may hide unbounded dirty work outside the contract.

`tidefs-performance-contract`, `validation/performance/no-hidden-queues.toml`,
and `xtask check-no-hidden-queues` are the current reusable foundations.
Issue #308 added local admission wiring, but stronger dirty-debt claims remain
blocked on runtime queue-depth evidence.

## Offload Boundary

Offload is a performance mechanism, never semantic authority.

The current validated claim is `offload.ready.non_authoritative.v1`. Its scope
is descriptor validation, buffer lease matching, completion validation, and CPU
reference kernels. It does not validate GPU/FPGA acceleration, DMA, kernel
integration, RDMA, storage runtime integration, or hardware equivalence.

Future accelerators must pass the same conformance vectors as the CPU
reference path and must be removable without changing storage correctness.

## Nexus Application

Codex Nexus must remain mechanics-only.

Do not hard-code this document, issue numbers, crate priority lists, product
topics, or release packets into Nexus scheduling code. Nexus should bend toward
this program only through the normal work-selection authorities:

- live GitHub issue and PR state;
- repo docs, including this document;
- claim registry and validation receipts;
- CI/check status;
- operator-owned dashboard focus bias.

If the operator wants to emphasize this program, update the dashboard focus
bias and prepare focused GitHub issues. The controller must still choose work
from live state and must still respect integration, PR stewardship, worker
capacity, and liveness rules.

## PR Checklist For This Program

Every PR that changes this program should answer:

1. Which existing authority is reused?
2. Which claim id, if any, is affected?
3. Which validation tier is the evidence?
4. Is any evidence model-only, harness-only, or runtime?
5. Are new queues registered or explicitly out of scope?
6. Are exact status/error mappings preserved?
7. Does any adapter start defining semantics directly?
8. Does any wording imply a stronger product claim than `validate-claim`
   allows?
9. Does the change require a runtime artifact, or is it intentionally only a
   model/source/tooling slice?
10. If formal tools are involved, are they optional and scoped to a stable
    target?

PRs that cannot answer these questions should stay draft or split into smaller
issues.

## Anti-Patterns

Reject these immediately:

- adding a new request type system beside the current VFS contract seed without
  an issue explaining why reuse is impossible;
- adding a second trace runner instead of extending `tidefs-trace-oracle`;
- treating model-only evidence as mounted runtime proof;
- turning future guide text into CI failure before the invariant is final;
- adding queues without registry coverage or a structured review reason;
- claiming performance from average throughput alone;
- making offload required for correctness;
- adding proof harness dependencies to normal product builds;
- letting one broad issue monopolize the verification program instead of
  splitting model, runtime, artifact, and claim-gate work.

## Current Non-Claims

This program does not say TideFS has completed:

- production crash safety;
- POSIX completeness;
- kernel-resident no-daemon operation;
- distributed production correctness;
- RDMA data-path readiness;
- GPU/FPGA acceleration;
- OpenZFS/Ceph-class reliability or performance;
- whole-system formal verification.

Those can become present-tense claims only through tracked issues, current
evidence artifacts, validation-tier review, claim registry updates, and
`validate-claim` receipts.


## Follow-Up Implementation Issue Map

The evidence-chain design recorded in this document defines a spine that
existing and planned follow-up issues implement. Issue #1274 refreshed the
map on 2026-06-28 from live GitHub issue/PR state, closed #1066, closed
#809/#810, `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, and source
inspection of the named producers. The live open issue search found no
producer-specific manifest-adoption issue except #1274 itself before this
refresh. The open PR file-set snapshot found no PR touching
`docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`,
`docs/CLAIMS_GATE_POLICY.md`, or `validation/claims.toml`; PR #1481 touches
`crates/tidefs-validation/src/performance_gate/**`, so the performance child
below avoids that path until the PR lands or a new non-overlapping split is
recorded.

### Unified Manifest Adoption Coverage

| Producer | Manifest authority | Live coverage from review | Current child or blocker |
| --- | --- | --- | --- |
| `tidefs-trace-oracle` | `TraceArtifactManifest` | Closed #731 emits schema-versioned model-only and harness-only trace manifests through `crates/tidefs-trace-oracle` and `xtask check-trace-oracle`. Runtime-tier mounted trace comparison remains separate because it needs real runtime backend execution and CI artifact references. | #1483 owns mounted/runtime `TraceArtifactManifest` integration. |
| `tidefs-crash-oracle` | `EvidenceArtifactManifest` | Closed #818 established the crash-oracle authority surface. `validation/claims.toml` already names crash `manifest_path` entries for some requirements, but `validation/artifacts/crash-oracle/` currently contains JSON/TOML evidence without the corresponding v2 `.manifest.json` files. | #1484 owns crash-oracle `EvidenceArtifactManifest` adoption and the model/runtime manifest boundary. |
| `tidefs-performance-contract` | `EvidenceArtifactManifest` | Closed #830 established the performance-contract authority surface. Performance artifacts and claim requirements still use plain registry/runtime records without claim-facing v2 manifests. | #1485 owns performance-contract `EvidenceArtifactManifest` adoption and avoids `performance_gate/**` while PR #1481 is open. |
| `tidefs-offload-core` | `EvidenceArtifactManifest` | Closed #828 established offload-core authority. The crate has `OffloadExternalBackendConformanceManifest` and offload TOML artifacts, but no claim-facing v2 manifest wrapper or `manifest_path` entries in the offload claim requirements. | #1486 owns offload-core `EvidenceArtifactManifest` wrapping. |
| `tidefs-env-fuse-model` | `EvidenceArtifactManifest` | Closed #811 committed `validation/artifacts/fuse/adapter-lifecycle-model.manifest.json` and wired the FUSE source-model claim requirement to that manifest path. | Covered; no #1274 child needed. |
| `tidefs-env-ublk-model` | `EvidenceArtifactManifest` | Closed #811 committed qid/tag and started-export source-model manifests under `validation/artifacts/ublk/`. Open #1185 separately owns a claims-registry consistency repair for the started-export evidence class list. | Covered for producer adoption; #1185 remains a claim-registry blocker, not a new adoption child. |
| `tidefs-distributed-model-check` | `EvidenceArtifactManifest` | Closed #811 committed `validation/artifacts/distributed/combined-safety-receipt.manifest.json` and wired the distributed source-model claim requirement to that manifest path. | Covered; no #1274 child needed. |
| `tidefs-two-node-harness` | `EvidenceArtifactManifest` | Closed #835 established two-node harness authority, but there is no focused issue or committed v2 manifest path for deterministic harness or QEMU carrier evidence. | #1487 owns two-node harness `EvidenceArtifactManifest` adoption. |
| Validation runtime artifacts | `EvidenceArtifactManifest` | Closed #809/#810 provide the shared v2 schema and claims-gate consumption. Closed #643, #644, and #646 cover xfstests, kernel-fsync, and RDMA workflow manifest lanes. Remaining producer-specific runtime artifacts are split through the crash, performance, offload, trace, and two-node children above. | Covered by the shared spine plus producer children; do not create one broad validation-runtime branch. |

### Producer Child Issues Opened By #1274

Each child below has a non-overlapping expected write set and records whether
it uses `EvidenceArtifactManifest` or `TraceArtifactManifest`.

| Issue | Producer | Manifest type | Expected write set boundary |
| ---: | --- | --- | --- |
| #1483 | `tidefs-trace-oracle` runtime traces | `TraceArtifactManifest` | `crates/tidefs-trace-oracle/**`, `xtask/tidefs-xtask/src/trace_oracle.rs`, `docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md`, `validation/claims.toml`, `validation/artifacts/trace-oracle/**`, and `.github/workflows/**` only for a focused trace-runtime artifact lane. |
| #1484 | `tidefs-crash-oracle` crash artifacts | `EvidenceArtifactManifest` | `crates/tidefs-crash-oracle/**`, `validation/artifacts/crash-oracle/**`, and `validation/claims.toml` only for crash manifest paths, blockers, and evidence-class consistency. |
| #1485 | `tidefs-performance-contract` performance evidence | `EvidenceArtifactManifest` | `crates/tidefs-performance-contract/**`, `validation/artifacts/performance/**`, and `validation/claims.toml` only for performance manifest paths, blockers, and evidence-class consistency. It must not edit `crates/tidefs-validation/src/performance_gate/**` while PR #1481 remains open. |
| #1486 | `tidefs-offload-core` offload evidence | `EvidenceArtifactManifest` | `crates/tidefs-offload-core/**`, `validation/artifacts/offload/**`, and `validation/claims.toml` only for offload manifest paths, blockers, and evidence-class consistency. |
| #1487 | `tidefs-two-node-harness` harness evidence | `EvidenceArtifactManifest` | `crates/tidefs-two-node-harness/**`, `validation/artifacts/two-node/**`, `validation/claims.toml`, and `.github/workflows/**` only for a focused two-node/QEMU manifest artifact lane. |

### Issue Creation Protocol

New follow-up issues must:

- Reference this document and issue #1066 as the design authority.
- Name the expected write set (crates, docs, and `validation/claims.toml`
  entries affected).
- State the evidence class and validation tier required.
- Declare non-overlap with the existing issues mapped above.
- Be prepared (acceptance criteria, behavior, write set, validation tier)
  before implementation starts.

Issue #1274 created #1483 through #1487 to close the current manifest adoption
map. Future workers should update the relevant child issue first if live
issue/PR state changes its write set or if implementation proves a producer
needs a different manifest boundary.

## Design Decision Record

This document was updated for issue #1066 on 2026-06-22 with the following
decisions recorded:

1. **Evidence chain**: Unified evidence manifest with typed claim anchors
   (Model A), enforced through `validation/claims.toml` and claims-gate
   tooling. Rejected: per-system artifact bundles with manual assembly
   (Model B).
2. **Evidence producers**: Eleven crates identified as primary evidence
   producers (see Evidence Producer and Consumer Map above).
3. **Evidence consumers**: Seven consumers/aggregators identified, with
   `validation/claims.toml` as the authoritative registry.
4. **Follow-up map**: Issue #1274 refreshed the manifest adoption map on
   2026-06-28. Closed #809/#810 provide the shared manifest spine, closed
   #811 and related workflow issues cover several producers, and #1483
   through #1487 own the remaining producer-specific manifest adoption gaps.
5. **Non-claims**: The non-claims section is preserved and extended with
   explicit boundaries for each producer crate:
   - `tidefs-model-core` does not claim runtime storage correctness.
   - `tidefs-crash-oracle` does not claim production crash safety without
     runtime crash-oracle evidence.
   - `tidefs-performance-contract` does not claim performance isolation
     without runtime queue-depth evidence.
   - `tidefs-offload-core` does not claim GPU/FPGA/DMA/RDMA acceleration.
   - `tidefs-env-fuse-model` and `tidefs-env-ublk-model` do not claim
     mounted runtime adapter correctness.
   - `tidefs-distributed-model-check` does not claim distributed production
     correctness.
   - `tidefs-two-node-harness` does not claim multi-node distributed
     production correctness.
   - `tidefs-trace-oracle` does not claim runtime crash safety or
     production performance regression detection without mounted-backend
     CI artifacts.
