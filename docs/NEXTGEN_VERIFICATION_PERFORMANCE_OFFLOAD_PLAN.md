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

| Program area | Current TideFS authority | Status and finishing direction |
| --- | --- | --- |
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
| Offload boundary | `crates/tidefs-offload-core`, `validation/artifacts/offload/*` from PR #324 | `offload.ready.non_authoritative.v1` is validated for descriptor, lease, completion, and CPU reference scope only. It is not GPU/FPGA/DMA/kernel/RDMA/storage-runtime evidence. |
| Distributed model | `crates/tidefs-distributed-model-check` from PRs #365 and #374 | Reuses settled placement/receipt types. Runtime distributed claims remain separate claim-gated work. |
| Verification engine | `crates/tidefs-verification-engine` | Existing object/replication verification machinery should be a consumer or artifact source, not a parallel claim authority. |

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
write/fsync/read/crash-recover evidence slice.

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
