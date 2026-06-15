# Nextgen Verification Contract Roadmap

Maturity: current planning authority for issue #281.

This document maps the nextgen verification, performance, and offload request
onto the current TideFS workspace. It is a docs-only staging contract. It does
not implement runtime behavior, and it does not make present-tense claims for
crash safety, performance isolation, kernel correctness, distributed
correctness, or accelerator correctness.

The purpose is to keep one evidence chain for future work:

1. adapter-neutral request contract;
2. executable model;
3. trace oracle;
4. claim registry;
5. crash oracle;
6. performance contract;
7. adapter environment models;
8. non-authoritative offload boundary.

## Authority Rules

Future work in this lane must extend the current TideFS authorities instead of
creating parallel systems:

| Roadmap area | Current anchor | Rule |
| --- | --- | --- |
| Request contract | `tidefs-types-vfs-core` and `tidefs-schema-codec-vfs` | Semantic requests, completions, errno mapping, and fixed-width records must reuse these crates. Do not create a second VFS request type system. |
| Executable model | current workspace product crates named in `docs/workspace-package-classification.md` | A model may be a proof harness, but it must consume the same request records and must not fork storage semantics into a separate product path. |
| Trace oracle | `tidefs-trace-oracle` | Trace corpus, replay, minimization, and comparison work must extend this oracle rather than adding another trace format or replay engine. |
| Claim registry | `docs/CLAIMS_GATE_POLICY.md`, `docs/REVIEW_TODO_REGISTER.md`, and `xtask check-claims-gate` | Claim ids in this file are planning ids only. Stronger wording requires a tracked issue, evidence, register status, and a claims-gate rule. |
| Crash oracle | TFR-008 recovery/cache-coherency register work and existing recovery/intent-log paths | Crash traces must prove restart behavior through current recovery authorities. This roadmap does not claim crash safety is complete. |
| Performance contract | `tidefs-validation` performance gates and `tidefs-background-scheduler` budget surfaces | Performance evidence must measure budgets and regressions through existing validation and scheduler surfaces. This roadmap does not claim performance isolation is complete. |
| Adapter environment models | `tidefs-ublk-abi`, current FUSE adapter surfaces, and kernel VFS issue lanes | Environment models generate legal adapter requests and lifecycle traces. They do not own filesystem semantics and must not bypass the request executor. |
| Offload boundary | `docs/RDMA_TRANSPORT_POSITION.md`, `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, and adapter ABIs | RDMA, hardware, copy offload, cache, and accelerator paths may improve cost. They must never be required for correctness. |

## Staged Architecture

Stage 0 ratifies this map. The only source of truth added by issue #281 is this
roadmap plus its review-register pointer. No runtime crate, adapter, kernel,
FUSE, placement, or local-filesystem behavior changes are part of this slice.

Stage 1 defines the TideFS-owned request contract. The contract is an
adapter-neutral request and completion vocabulary for filesystem semantics.
`tidefs-types-vfs-core` owns portable record types, and
`tidefs-schema-codec-vfs` owns VFS errno and fixed-width codec hooks. FUSE,
ublk, kernel VFS, CLI, and future RPC adapters translate into this vocabulary;
they do not define competing semantics.

Stage 2 adds an executable model only after a focused issue names its scope.
The model should be small enough to replay request sequences and compare
semantic outcomes, but it must use current TideFS request records and current
workspace package roles. It may expose gaps; it must not become a second
filesystem implementation that carries release claims.

Stage 3 extends `tidefs-trace-oracle` into the comparison surface for the
request contract. Golden traces, minimized failures, adapter-emitted traces,
and crash/restart traces should share one manifest and replay discipline.
Trace fields may record adapter environment facts, but equivalence remains at
the TideFS request/completion boundary.

Stage 4 keeps claim ids explicit and blocked until evidence exists. The claim
registry for this roadmap is the table below, backed by
`docs/REVIEW_TODO_REGISTER.md` and guarded by `xtask check-claims-gate` before
any publishing-facing stronger wording appears.

Stage 5 adds a crash oracle. Crash traces should cover pre-crash request
prefixes, injected stop points, reopen/replay, and post-recovery comparison
through the same trace oracle. This remains blocked by TFR-008 and issue-scoped
recovery work; issue #279 is useful input, not full crash-safety closure.

Stage 6 adds a performance contract. Performance traces should record
workload shape, budget class, background-service activity, and regression
thresholds through `tidefs-validation` and `tidefs-background-scheduler`.
The contract must distinguish optimization from correctness and must not state
that TideFS has performance isolation until the relevant evidence exists.

Stage 7 adds adapter environment models. A FUSE model, ublk model, kernel VFS
model, and future RPC model may generate legal environment lifecycles, request
ordering, teardown, retry, and capability traces. Their job is to prove that
adapters translate into TideFS-owned requests; adapter models do not mutate
storage directly and do not define semantic truth.

Stage 8 records the non-authoritative offload boundary. Copy offload,
accelerator paths, RDMA, kernel helpers, and cache/materialization shortcuts
can be performance mechanisms only. Correctness evidence must still pass when
the offload is absent, disabled, or replaced by a slower portable path.

## Dependency And Order Table

| Order | Lane | Live state on 2026-06-15 | Roadmap dependency |
| ---: | --- | --- | --- |
| 1 | #276 `workspace: resolve scaffold-transitional type crates` | Closed. `docs/workspace-package-classification.md` is current package-role authority. | Use package roles from the classification doc. Do not create another package inventory for this roadmap. |
| 2 | #278 plus PR #280 `tidefsctl: gate command-classification docs against registry drift` | #278 closed; PR #280 merged. | Claims-gate and tidefsctl classification text have landed. This issue still leaves `docs/CLAIMS_GATE_POLICY.md` untouched. |
| 3 | #254 plus PR #269 `fuse xfstests: burn down mounted generic smoke row failures` | #254 closed; PR #269 merged. | FUSE environment-model work can follow in a separate issue, but #281 does not edit FUSE code or xfstests behavior. |
| 4 | #279 `storage: route recovery probes through transform authority` | Closed. | Crash-oracle planning must route recovery probes through transform authority; this is not full recovery closure. |
| 5 | #275 `kernel-vfs: prove truncate invalidation through mounted page cache` | Closed. | Kernel environment-model work can use this as one input, while TFR-018 remains open for broad kernel/POSIX proof. |
| 6 | #91 `local-filesystem: retire one-directory default pool bridge` | Open. | Executable-model and request-contract work must not rely on the retired directory-pool bridge as semantic authority. |
| 7 | #238 `local-filesystem: make zero-length file writes a true no-op` | Open. | Request traces and executable-model claims stay blocked for write-edge completeness until this lane or an equivalent proof lands. |
| 8 | #17 `placement: allocate every stripe from the whole pool redundancy policy` and #18 `distributed: make placement receipts drive rebake rebuild and reclaim` | Both open. | Distributed correctness, rebake, rebuild, reclaim, and placement-receipt claims remain blocked. |

## Planned Claim Registry

These ids are high-value planning handles. Their status is `planned-blocked`
until issue-scoped evidence exists. This table is not a claims-gate allow-list.

| Claim id | Status | Claim family | Blocking evidence before stronger wording |
| --- | --- | --- | --- |
| NVC-CLAIM-001 | planned-blocked | Request contract completeness | A current issue must define the request/completion set against `tidefs-types-vfs-core` and `tidefs-schema-codec-vfs`, with adapter translations checked against it. |
| NVC-CLAIM-002 | planned-blocked | Executable model equivalence | A focused model must replay request traces and compare results without carrying independent filesystem semantics or release claims. |
| NVC-CLAIM-003 | planned-blocked | Trace oracle coverage | `tidefs-trace-oracle` must own the corpus, manifest, replay, and minimization for request-contract traces and adapter-generated traces. |
| NVC-CLAIM-004 | planned-blocked | Crash oracle and recovery | Crash/restart traces must prove requested recovery behavior through current recovery authorities; TFR-008 remains open. |
| NVC-CLAIM-005 | planned-blocked | Performance contract and isolation | `tidefs-validation` and `tidefs-background-scheduler` must record budgets, baselines, and regressions before any performance-isolation claim. |
| NVC-CLAIM-006 | planned-blocked | Kernel adapter correctness | Kernel environment traces and mounted runtime evidence must cover the requested behavior; TFR-018 remains open. |
| NVC-CLAIM-007 | planned-blocked | Distributed placement/rebuild correctness | #17, #18, TFR-017, and related receipt/rebake evidence must land before distributed correctness wording. |
| NVC-CLAIM-008 | planned-blocked | Offload and accelerator independence | Correctness must be shown without RDMA, hardware offload, copy offload, or cache acceleration as a required semantic authority. |

## Non-Claims

This roadmap does not say that TideFS has completed:

- crash safety;
- performance isolation;
- kernel correctness;
- distributed correctness;
- accelerator correctness;
- OpenZFS/Ceph-class capability.

Those topics may appear in future issues only as planned work, blocked claims,
or evidence-backed improvements that stay within `docs/CLAIMS_GATE_POLICY.md`.
