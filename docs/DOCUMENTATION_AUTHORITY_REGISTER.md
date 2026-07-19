# Documentation Authority Register

This register is a specialized reference for classifying surviving documents.
It is not ordinary baseline reading, product authority, project status, or a
definition-of-done checklist. `README.md` is the sole product-shape authority;
load it only for a documentation-classification task or an actual publication,
release-candidate, support, or comparison review.

## Authority Rule

Imported documents are review inputs unless a focused, source-backed
classification below gives them a narrow current scope. Documents under
`docs/design/`, root documents ending in `_DESIGN.md`, issue-era
implementation plans, old status matrices, coordination packets, closeout
snapshots, and Forgejo-era milestone updates are historical input by default
even when their text says `Maturity:`, `Status: sealed`, `canonical`, `single
authoritative`, phase complete, implemented, or current. That wording is
imported context, not current authority.

A document becomes current policy or current spec only through source-backed
classification that names the narrow scope being promoted. Current source and
the smallest relevant carrier or invariant test establish current behavior.
For an actual publication, tag, release candidate, or externally consumed
support or comparison statement, use `docs/CLAIMS_GATE_POLICY.md` and evidence
for that exact statement. Those publication guardrails do not establish
behavior or complete ordinary development work.

## Classification States

Use exactly one state when auditing a document:

- Current policy: binding rule that matches current source and repo policy.
- Current spec: design or implementation contract that matches current source
  behavior and recorded evidence.
- Historical input: useful design or audit material that must not be cited as
  current status.
- Missing: referenced document path that is absent from the repository; record
  the gap so citations are not treated as authority.
- Delete candidate: stale duplicate, obsolete closeout note, or scaffold text
  whose useful content has already moved elsewhere.

Classification notes may also record a document handling role. Evidence-only
documents record authority evidence, old paths, retired crates, issue
closeouts, or generated-state inputs without becoming current status surfaces.
Generated or derived documents are produced from registry/source data and must
not become hand-authored independent policy. These handling roles do not add
extra authority states: each document still uses exactly one state above.

## Review Method

Classify documents in focused commits and do not mix classification with
runtime implementation. Verify a proposed current-policy or current-spec scope
against current source and repository policy; where it asserts behavior, use
the smallest relevant carrier or invariant test. If the scope cannot be
established, leave the document as historical input; do not create or extend a
gate-review history.

Consolidation work must collapse duplicate truth surfaces instead of creating
new status files or generated authority. Treat broad design docs, old status
matrices, coordination packets, closeout snapshots, and issue-era
implementation plans as historical input or delete candidates until a focused
issue classifies their exact scope. Delete after useful current content has
moved or the file is obsolete scaffold/closeout material; keep deleted-path
lineage in git, issues, and PRs instead of preserving a live register row for
every deleted file.

## Evidence-Only Surfaces

The documentation-authority drift guard treats these files as evidence-only
records rather than live product or status documents:

- `docs/workspace-package-classification.md`
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
- `docs/REVIEW_TODO_REGISTER.md`

They may record retired crates, missing paths, and review debt without promoting
those records to current product authority. Deleted-path lineage belongs in git
history and the linked GitHub issues and pull requests, not in an append-only
register ledger.

## Classified Authority Slices

### Live-Looking Authority Marker Classifications (TFR-019 / #1595)

Issue #1595 also hardened the doc-authority drift guard for unclassified
Markdown files that declare themselves current, re-evaluated, canonical, or
single-source authority. The following surviving docs keep narrow current-spec
classification because source references or implementation-gate coordination
still consume their exact boundaries. This does not promote broader runtime,
release, successor, comparator, production, or parity claims.

| Path | State | Classification note |
|---|---|---|
| `docs/cache-authority-model.md` | Current spec | Binding only for the cache authority class vocabulary and cache-layer ownership table consumed by current cache, local-filesystem, and FUSE adapter source comments. It is not an end-to-end page-cache/writeback/mmap durability proof, kernel page-cache completion claim, performance claim, or production readiness evidence. |
| `docs/SNAPSHOT_NAMESPACE_BROWSING.md` | Current spec | Binding only as the issue #768 snapshot browsing namespace decision and follow-up map: transparent read-only browsing is the chosen design target and mutation/refusal boundary. It is not runtime validation, ZFS parity evidence, snapshot lifecycle proof, or release-readiness evidence. |

### Request Contract Authority (TFR-019 / #1136)

Classified for TFR-019 / GitHub issue #1136 on 2026-06-25 after reviewing this
register's authority rule and review method, `docs/REQUEST_CONTRACT.md`,
`docs/INDEX.md`, the verification/model references in
`docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`, and
`docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md`, the claim registry and scanned
claims-gate document list, the source anchors in `crates/tidefs-types-vfs-core/`
and `crates/tidefs-schema-codec-vfs/`, the model references in
`crates/tidefs-env-fuse-model/`, `crates/tidefs-env-ublk-model/`,
`crates/tidefs-model-core/`, and `crates/tidefs-trace-oracle/`, and closed
GitHub issues #282, #528, #751, and #1066 as historical lineage evidence. This
slice is documentation/source inspection only; it does not change source,
claims-gate requirements, runtime behavior, or validation promises.

| Path | State | Classification note |
|---|---|---|
| `docs/REQUEST_CONTRACT.md` | Current spec | Binding only for the TideFS-owned request/completion contract shape: `ContractVersion(1)`, `RequestMetadata`, `RequestEnvelope`, `TideRequest`, `TideCompletion`, fixed-width little-endian v1 request envelopes at 128 bytes, fixed-width little-endian v1 completions at 96 bytes, decoder rejection of unsupported versions, wrong byte lengths, encoded-length drift, unknown metadata/status tags, and non-zero reserved fields, and explicit unsupported request payloads. The checked source anchors are `tidefs-types-vfs-core` for the portable records and `tidefs-schema-codec-vfs` for the v1 codecs and golden-vector self-checks; the checked verification/model docs and FUSE, uBLK, model-core, and trace-oracle references consume that boundary as contract-shape or model/harness evidence. This is not authority for FUSE, ublk, kernel VFS, RPC, storage, placement, rebuild, reclaim, or offload runtime rewiring; it is not runtime adapter validation, mounted behavior proof, production ABI freeze, release-readiness evidence, or claims-gate claim closure. |

### Checksum and BLAKE3 Authority

Classified for TFR-019 / GitHub issue #332 on 2026-06-16 after checking live
source behavior, `validation/claims.toml`, and `xtask check-claims-gate`.

| Path | State | Classification note |
|---|---|---|
| `docs/BLAKE3_USAGE_POLICY.md` | Current policy | Binding only as a BLAKE3 placement and review policy. It is not implementation-status evidence and does not validate production end-to-end checksum, scrub self-heal, erasure-coded integrity, or tamper-proof root claims. Because this is promoted to current policy, it is scanned by the claims gate. |
| `docs/CHECKSUM_ARCHITECTURE_DESIGN.md` | Historical input | Deferred in #1720 because active issue #1722 owns the remaining `xtask/tidefs-xtask/src/cluster.rs` citations. `docs/BLAKE3_USAGE_POLICY.md` is the current BLAKE3 placement policy; this imported G3 design target is not production checksum, repair, erasure, committed-root integrity, or release authority. |

### Kernel And Preview UAPI Authority

Classified for TFR-011 / TFR-019 / GitHub issue #337 on 2026-06-16 after
checking live source behavior, `docs/GITHUB_CI.md`,
`docs/REVIEW_TODO_REGISTER.md`, `validation/claims.toml`, and the current
claims gate. This slice does not change the claims-gate scanned surface:
`docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md` remains the only scanned document in
this set.

| Path | State | Classification note |
|---|---|---|
| `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md` | Current spec | Binding only for the checked tidefsctl command classification/admission table and the current non-release VFS fixed-width codec hook description. It is scanned by the claims gate and must keep explicit non-claim wording for production Linux ioctl/statx/ublk ABI freeze, kernel module ABI freeze, distributed operator UAPI finality, and kernelspace readiness. |
| `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md` | Current spec | Target architecture and evidence-tier map for kernel-resident pool-engine work. Current implementation evidence is the narrow Linux 7.0 QEMU configured-pool smoke described in `docs/GITHUB_CI.md`; full-kernel, daemonless storage parity, xfstests, crash/replay, object/extent engine, block-volume export, and production-readiness claims remain outside this status. |
| `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md` | Current policy | Binding only as the Linux 7.0 kernel development workflow: external-module or Linux-branch ownership, out-of-repo build output, disposable QEMU guests, and Nix/QEMU acceptance gates. It is not runtime maturity evidence and does not require broad kernel validation for documentation-only slices. |

### Operator UAPI Authority Decision

Classified for TFR-011 / TFR-019 / GitHub issue #661 on 2026-06-20 after
reviewing the landed issue #656 decision, TFR-011/TFR-019 register notes, the
checked `tidefsctl` command registry/admission evidence referenced by the
decision, and the current claims-gate scanned surface. This slice does not
change command behavior or claims-gate scanned documents; issue #658 owns any
claims-gate coverage change for this decision artifact.

| Path | State | Classification note |
|---|---|---|
| `docs/OPERATOR_UAPI_AUTHORITY.md` | Current spec | Binding only as the current pre-alpha operator UAPI boundary decision: `COMMAND_SURFACES` remains the `tidefsctl` command-surface authority, `command_admission` remains the privileged-admission authority, diagnostics/prototypes must keep weaker class and routing claims, and imported documents still require this register for authority. It is not a production Linux ioctl/statx/ublk/FUSE/kernel ABI freeze, kernelspace readiness evidence, distributed operator maturity evidence, runtime-fed remote policy authority, or release-readiness claim. |

### Control Format And JSON Policy

Classified on 2026-06-30 after checking the current README/AGENTS pre-alpha
policy, unreleased-surface guardrail, on-disk format policy, operator UAPI
decision, operator product-surface decision, and bounded source inspection of
current live-owner, local-filesystem live-admin, device-removal, rebuild, and
VFS control hooks. This slice records a policy guardrail only; it does not
change source behavior or close any release-readiness claim.

| Path | State | Classification note |
|---|---|---|
| `docs/CONTROL_FORMAT_AND_JSON_POLICY.md` | Current policy | Binding only as the JSON/control-format review guardrail: JSON is allowed for explicit evidence, diagnostics, support bundles, traces, and expert/machine export, but not as ordinary operator UX, a hot-path protocol, a final wire/control carrier, or durable product format. Existing JSON live-admin and local record uses are pre-alpha transitional debt until a source issue replaces or graduates them. This policy is not implementation evidence, production ABI authority, on-disk compatibility authority, or a release-readiness claim. |

### Initial Classification Slice (TFR-019 / #497)

Classified for TFR-019 / GitHub issue #497 on 2026-06-17. Documents were
reviewed for maturity labels, stale Forgejo references, dead cross-references,
current source alignment, and claims-gate coverage. Where live source
verification was too large for this slice, the document was left as historical
input. One document was promoted to current policy after verifying the claims
gate actively scans and enforces it; one empty scaffold document was classified
as a delete candidate. This slice does not change the claims-gate scanned
surface beyond adding `docs/CLAIMS_GATE_POLICY.md`, which was already scanned.

**Policy, operator, and security-facing docs**

| Path | State | Classification note |
|---|---|---|
| `docs/CLAIMS_GATE_POLICY.md` | Current policy | Binding claims-gate guardrail enforced by `xtask check-claims-gate`. The scanner hard-codes a policy spec constant, verifies this file exists, and checks that the required gate text is present. Because this is promoted to current policy, it is scanned by the claims gate (it was already in the scanned-surface list). |
| `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` | Current policy | Design decision #1267 recording the current runtime-fed operator product-surface boundary after the OW-307D blocker map. States that no runtime-fed operator product surface exists, the P10-04 truth-surface law is missing from the repository, and no product carrier class is selectable until transport/cluster authority and the P10-04 gap close. The operator/UAPI command boundary is closed for the current pre-alpha command surface, but that closeout is not a runtime-fed product carrier. |
| `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` | Missing | Truth-surface law reference absent from the repository. Issue #1270 records the gap: the law expected to define mandatory surface classes, provenance/exactness/freshness rendering, carrier verification, and the `truth_view` concept does not exist, so citations to this path are not current authority. |

**Architecture, design, and feature docs**

| Path | State | Classification note |
|---|---|---|
| `docs/HUMAN_TERMINOLOGY.md` | Historical input | Frozen imported terminology history. Current terminology-check signal lives in source-owned structured entries in `xtask/tidefs-xtask/src/terminology.rs` plus current docs, demo, and API checks; this file is not a checker input, current source authority, or product wording. Some listed crate paths are retired or future-only. |
| `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md` | Historical input | Imported production-design FUSE binding strategy describing the `fuser`-based binding, capability negotiation, and feature matrix. Useful reference, but full per-capability source alignment verification is too large for this slice. |
| `docs/DEBUGGING_WORKFLOWS.md` | Deleted | Deleted by #1779 after #1725 merged and #1722 closed. Current repository build entry points live in `README.md`; CI lane and artifact authority lives in `docs/GITHUB_CI.md`; xfstests dispatch and artifact details live in `docs/XFSTESTS_DISPATCH_CONTRACT.md`; source-owned command help and scoreboard behavior remain in the relevant binaries and validation code. |
| `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` | Current spec | Scoped source-backed summary for the current pool-label, pool-scan/import, local import/export, and device-manager code paths. It is not product-readiness evidence for hot spares, evacuation, cluster ownership, online topology conversion, hardware-failure survival, availability, operational safety, or incumbent-comparison claims. |

### Remaining Imported Design Surface (TFR-019 / #512)

Classified for TFR-019 / GitHub issue #512 on 2026-06-18. This slice covers
the remaining high-impact imported design surface outside the #497 slice:
architecture/local-format references, block-volume and ublk adapter documents,
FUSE/POSIX adapter documents, kernel/UAPI boundary documents, and
operator/placement documents. Current spec and current policy classifications
are deliberately scoped to the source-boundary or guardrail named in each row;
they do not validate production readiness, full-kernel residency, broad
xfstests coverage, distributed behavior, or runtime crash claims.

**Architecture, kernel, and local-format references**

| Path | State | Classification note |
|---|---|---|
| `docs/ARCHITECTURE.md` | Current spec | Binding only as the source-backed high-level workspace, app, layer, and runtime-mode ownership map. It is not evidence that every listed crate is complete, kernel-resident, production-ready, distributed, release-ready, or validated by runtime CI. |

**Block-volume adapter and ublk source-boundary docs**

| Path | State | Classification note |
|---|---|---|
| `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md` | Current spec | Scoped current spec for the started-export admission artifact and fail-closed verification path. It does not close broader block-volume runtime validation. |

**FUSE/POSIX adapter docs**

| Path | State | Classification note |
|---|---|---|
| `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` | Current policy | Binding only as the adapter-boundary guardrail that prevents runtime FUSE handlers from bypassing the TideFS request/VfsEngine path into storage mutation authority. It does not close xfstests rows or broader POSIX/FUSE completeness. |
| `docs/FUSE_LSEEK_PC004B.md` | Current spec | Scoped current spec for the non-release dense-file preview `lseek` behavior described in the file. It does not claim sparse-file fidelity or parent POSIX-complete FUSE closure. |

**Operator, placement, and distributed-runtime docs**

| Path | State | Classification note |
|---|---|---|
| `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` | Current spec | Normative authority for the native storage-intent policy surface introduced by GitHub issue #839: non-claim boundaries, earned receipt honesty, media-role legality, POSIX sync and unsafe-mode floors, evidence-query cuts, RAM authority classes, decision-frontier/accountability, source-retirement, result/refusal projection, operator explanation, validation classes, and successor/comparator guardrails. It is not runtime implementation evidence, a POSIX sync validation claim, a distributed availability claim, a completed fault-validation claim, a roadmap, or a performance superiority claim. |
| `docs/STORAGE_INTENT_SERVICE_OBJECTIVE_DESIGN.md` | Current spec | Scoped current spec for GitHub issue #915 service-objective evidence: objective identity, workload and operation scope, latency percentile/tail, throughput/burst/dwell, topology/media/proximity, RPO/RTO, isolation, capacity, cost, wear, decision/action, measurement, comparator, claim, and typed refusal requirements. It is not runtime implementation evidence, a performance-validation artifact, or a superiority claim over OpenZFS, Ceph, DRBD, or any other system. |
| `docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md` | Current spec | Scoped current spec for GitHub issue #920 result/refusal evidence: caller-visible outcome identity, policy/query/decision/receipt refs, degraded-visible state, service-objective/admission/action blockers, response-registry projection, retryability, caller compression, and retention/audit requirements. It is not runtime implementation evidence, a response-registry runtime, a POSIX errno validation artifact, or a product-readiness claim. |
| `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md` | Current spec | Scoped current spec for deterministic joint quorum-set identity in `crates/tidefs-membership-epoch`. It does not validate a full cluster-membership service. |
| `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` | Current spec | Scoped current spec for pool-wide placement contract and property-tested local model behavior. It does not prove distributed availability, rebake, recovery, or operator lifecycle behavior. |
| `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` | Current spec | Scoped current spec for the issue #18 placement receipt authority split, including the shared `PlacementReceiptRef` policy-satisfying gate and remaining follow-up issues #674, #675, and #676. It is not a closure claim for distributed availability, rebuild, rebake, reclaim, or runtime validation. |
| `docs/RAM_AUTHORITY_DESIGN.md` | Current spec | Scoped current spec for the issue #847 RAM authority boundary: `ram-volatile-local`, `ram-volatile-replicated`, `ram-intent-backed`, and `pmem-durable` semantics, receipts, failure behavior, policy-transition rules, resource-governor boundaries, and operator explanation requirements. It is not runtime implementation, PMem platform validation, distributed quorum proof, or POSIX durability evidence. |

## Incumbent Comparison Audit Slice (#931)

Incumbent-comparison material is historical input, not TideFS product evidence.
Current source and focused carrier tests establish behavior. Only an actual
publication, tag, release candidate, or externally consumed comparison
statement uses the matching `storage.local.successor_comparator.v1` or
`storage.distributed.successor_comparator.v1` claim and comparator evidence.
That publication guardrail does not complete ordinary development work.

### Background Service Framework Scheduler Authority (TFR-019 / #1537)

Classified for TFR-019 / GitHub issue #1537 on 2026-06-29 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, repository review history, the root
background-service redirect, the tracked deleted background-service design
family, live scheduler source in
`crates/tidefs-background-scheduler/src/lib.rs`,
`crates/tidefs-background-scheduler/src/scheduler.rs`,
`crates/tidefs-background-scheduler/src/scheduling.rs`, and
`crates/tidefs-background-scheduler/src/multi_threaded.rs`,
`validation/claims.toml`, and `docs/CLAIM_REGISTRY.md`.

Selected alternative: keep the imported background-service framework design
family as historical input and retarget the reader-facing redirect/design entry
points to this authority boundary. The live `tidefs-background-scheduler` source
does contain a narrow source-matched scheduler contract: `ServicePriority`,
`ServiceBudget`, `TickReport`, `CycleReport`, `BackgroundService`,
`IncrementalJobAdapter`, `BackgroundScheduler::{register, submit, poll,
run_cycle, tick_if_idle}`, durable dispatch registration helpers, the
`scheduling.rs` lane queue and `Schedulable`/`PollResult` contract, and the
feature-gated `multi_threaded.rs` scheduler types. That contract is current
source behavior, not a promotion of the imported design documents to current
spec.

| Path | State | Classification note |
|---|---|---|
| `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` | Current spec | Scoped source-backed summary for the current background scheduler and incremental-job contract in `crates/tidefs-background-scheduler`, `crates/tidefs-incremental-job-core`, and `crates/tidefs-types-incremental-job-core`. It is not release-readiness evidence or proof that every maintenance subsystem is wired into mounted runtime behavior. |

### Release Readiness Verdict Contract (#1279)

Classified for GitHub issue #1279 on 2026-06-24 after reviewing this register's
authority rule and review method, `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`, `docs/CLAIMS_GATE_POLICY.md`,
the source-backed performance gate, `docs/GITHUB_CI.md`,
`docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, the current open PR and issue
validation conventions, and bounded source inspection of
`crates/tidefs-validation/src/performance_gate/runner.rs`. This slice classifies
the verdict contract only; classification rows for the five evidence-input
documents are deferred to a follow-up issue mapped in the contract's follow-up
issue map. This slice does not edit the evidence-input documents beyond the
cross-reference additions recorded in #1279.

| Path | State | Classification note |
|---|---|---|
| `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` | Current policy | Design decision #1279 defining the release-readiness verdict boundary. Names the verdict owner, required evidence families, explicit non-claims, and the distinction between gate-local readiness receipts (such as performance-gate `GateReceipt.perf_gate_ready`, claims-gate claim status, and release-candidate evidence index) and whole-product admission. States that no release-readiness verdict exists as of 2026-06-24, that TideFS is not release-ready, and that no automated gate, CI workflow, or generated artifact may render an unqualified release-readiness claim without the verdict owner's recorded decision. Records closed follow-ups #1283 and #1284 for the scoped performance-gate receipt rename/rendering work and release-facing documentation register classifications. The contract is a design/decision artifact; it does not implement a product surface, widen publishing claims, or change `validation/claims.toml`. |

### Release-Facing Evidence Inputs (#1284)

Classified for GitHub issue #1284 on 2026-06-24 after reviewing this register's
authority rule and review method, `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`
(#1279), the release-facing evidence-input documents named by the verdict
contract, `docs/CLAIMS_GATE_POLICY.md` (already classified as Current policy),
and bounded source/doc inspection of `.github/workflows/release-candidate.yml`,
`crates/tidefs-validation/src/performance_gate/runner.rs`, and the current
open PR and issue validation conventions. This slice added classification rows
for the release-facing evidence-input documents that the release-readiness
verdict contract (#1279) identified as required evidence families. The
performance-gate-local `GateReceipt.perf_gate_ready` field rename and scoped
rendering work was completed by #1283. Source-backed performance-gate authority
remains with the validation crate, xtask behavior, release-candidate evidence,
and the release-readiness verdict contract. This slice does not edit runtime source, GitHub workflows,
`validation/claims.toml`, generated claim registry files, or unrelated
documents.

| Path | State | Classification note |
|---|---|---|
| `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` | Current spec | Documents how the Release Candidate workflow (`release-candidate.yml`) produces and indexes evidence across `smoke` and `full` profiles. Records lane job attributes (rust-smoke, nix, qemu, xfstests, rdma), artifact upload details, evidence index shape, profile selection logic, concurrency rules, and retention policies. Explicitly states the release-candidate evidence index is a **gate input, not a gate verdict**. Live-source inspection of `.github/workflows/release-candidate.yml` and the referenced lane workflows confirms the documented attributes match current workflow YAML. The contract does not make a product-readiness claim; it describes how evidence is collected so gate auditors can interpret index artifacts without tracing through YAML. The four lane-local manifest owner issues (643-646) are recorded without checking current issue state; gate auditors should verify at decision time. |
| `docs/UNRELEASED_AUTHORITY_POLICY.md` | Current policy | Binding guardrail that forbids adding or preserving legacy, backward-compatibility, migration, downgrade, or fallback behavior for unreleased TideFS data by default. Requires released external boundaries (Linux, POSIX, kernel, third-party), shipped wire/format/operator surfaces, or a temporary bridge explicitly tracked by a GitHub issue before compatibility work is permitted. Names pre-release code paths explicitly (current authority, retired pre-release path, historical input, receiptless path) instead of using "legacy." Includes a review checklist for compatibility additions. Classified as current policy consistent with its own "current policy guardrail" maturity label and live enforcement through PR review conventions. |
| `docs/GITHUB_CI.md` | Current policy | Documents the live GitHub Actions CI surface: secret boundary (GitHub is not a TideFS secret store), self-hosted runner contract, workflow shape (`Rust Fast`, `Clippy`, `Focused Rust`, `Focused Claim Validation`, `Secret Policy`, `QEMU Smoke`, `xfstests`, `RDMA`, `Release Candidate`), path-filtered PR validation, draft-PR CI skip rules, and `TIDEFS_SELF_HOSTED_READY` gating. Live-source inspection of the named workflow YAML files confirms the documented attributes match current behavior. The Release Candidate workflow is a manual-only self-hosted composition that uploads a `release-candidate-evidence-index` artifact without making a product-readiness claim. This document is a binding CI reference that complements the workflow YAML; it is not a product admission or release-readiness verdict. |

### Cargo-Deny ADR Authority (TFR-019 / #1935)

Classified on 2026-07-12 after checking ADR-0006, `docs/GITHUB_CI.md`,
`.github/workflows/dependency-license.yml`, `docs/LICENSING.md`, `COPYING`, and
`deny.toml`. This slice keeps the ADR as a narrow dependency-license policy
decision record; it does not change workflow behavior, license policy, or
claims-gate coverage.

| Path | State | Classification note |
|---|---|---|
| `docs/adr/0006-license-compliance-cargo-deny.md` | Current policy | Binding only as the cargo-deny dependency-license decision record: TideFS uses `cargo deny check licenses` for dependency-license validation, and accepted dependency-license allowlist/rule changes flow through `deny.toml`. `deny.toml` remains the concrete dependency-license allowlist and rule source, while `COPYING` and `docs/LICENSING.md` remain TideFS project-license authority. This ADR is not a supply-chain completeness claim, dependency-advisory remediation policy, release-readiness evidence, production-readiness evidence, or product capability claim. |
