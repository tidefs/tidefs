# Documentation Authority Register

Date: 2026-06-21

This register is the TFR-019 queue for imported documents that still need
authority classification. It is deliberately narrow: it does not make the
listed documents current policy, and it does not close any storage behavior
claim.

## Authority Rule

The active entry points are `README.md`, `AGENTS.md`, `docs/LICENSING.md`,
`docs/REVIEW_TODO_REGISTER.md`, `docs/WHOLE_REPO_REVIEW.md`,
`docs/SUCCESSOR_LOCKDOWN_AND_DOC_CONSOLIDATION.md`, and this file.

The active TideFS Book authoring decision is `docs/book/README.adoc`. The
assembled book source starts at `docs/book/tidefs-book.adoc`; book chapters are
current only for the narrow subject they state and must not promote imported
historical design material without this register classifying it.

All other imported documents are review inputs until classified here or in a
small follow-up commit tied to TFR-019.

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

Classify documents in focused commits. Do not mix doc classification with
runtime implementation except for narrow claim-gate coverage updates required
by the classification itself.

Before promoting a document to current policy or current spec, check the live
source behavior, `validation/claims.toml`, and the claims gate. If that review is
too large for the current slice, leave the document as historical input and
record the blocker in `docs/REVIEW_TODO_REGISTER.md` or
`docs/WHOLE_REPO_REVIEW.md`.

## Successor Lockdown And Documentation Consolidation (#1580)

Classified for TFR-019 / GitHub issue #1580 on 2026-06-30 after reviewing the
current claim registry, `validation/claims.toml`, the storage-intent policy
authority, the release-readiness verdict contract, the product-admission proof
train map, this register, `docs/INDEX.md`, `docs/WHOLE_REPO_REVIEW.md`, and live
GitHub issue/PR state. This slice adds a current policy guardrail and does not
classify every imported document, validate any successor claim, or close
TFR-019.

| Path | State | Classification note |
|---|---|---|
| `docs/SUCCESSOR_LOCKDOWN_AND_DOC_CONSOLIDATION.md` | Current policy | Binding guardrail that routes OpenZFS, Ceph, DRBD, local-filesystem successor/comparator wording through `storage.intent.successor_comparator.v1`, separates normal issue/PR validation from product-gate evidence, and makes documentation consolidation a TFR-019 authority-classification workstream. It does not validate the successor comparator claim, declare release or production readiness, classify every imported document, or promote broad historical design material. |

## Doc-Authority Drift Cleanup Coordination (#952)

Recorded on 2026-06-22 for the `check-doc-authority-drift` follow-up from PR
#950. This section is a coordination map only: it does not promote or demote
any document, does not change scanner behavior, and does not make product
readiness claims.

For this guard, current docs are scanned unless this register classifies them
as historical input or delete candidates. Historical-input docs and
delete-candidate docs are intentional skip surfaces for the guard; they may
preserve retired paths as review material but must not be cited as current
status. Evidence-only docs are `docs/workspace-package-classification.md`,
`docs/REVIEW_TODO_REGISTER.md`, this register, and
`docs/WHOLE_REPO_REVIEW.md`; those files intentionally record retired crates,
deleted docs, and old paths as authority evidence rather than rewrite targets.

The #952 live-doc cleanup is split into exact-file child slices. Those paths
stay out of this coordination slice:

- #1015 owns current-doc retired scaffold root references in
  `docs/ARCHITECTURE.md`.
- #1016 owns deleted status/matrix links in `docs/USER_MANUAL.md`.
- #1017 owns the visible historical-input treatment for retired crate paths in
  `docs/HUMAN_TERMINOLOGY.md`.
- #1018 owns historical/evidence treatment for retired type-root consolidation
  records in `docs/crates/types-core-consolidation-plan.md`.
- #1019 owns historical/evidence treatment for retired type-root dependency
  tables in
  `docs/design/crate-dependency-graph-ownership-boundaries.md`.
- #1020 owns retired type-root workspace prose in
  `docs/crates/workspace-structure.md`.
- #1021 owns the deleted `docs/FEATURE_MATRIX.md` reference in
  `docs/design/deterministic-cluster-simnet-protocol-correctness-testing.md`.
- #1022 owns deleted status/matrix closeout references in
  `docs/design/deferred-cleanup-work-queues.md`.
- #1023 owns feature-matrix/status wording in
  `docs/design/persistent-orphan-index-consolidated-design.md`.
- #1024 owns deleted status/matrix delivery outputs in
  `docs/design/node-lifecycle-management.md`.
- #1025 owns deleted status/matrix update targets in
  `docs/design/deferred-cleanup-background-service-scheduling.md`.

Bounded source/doc inspection for this coordination slice also found older
status/matrix references outside the #1015-#1025 child map. Issue #1586 later
deleted the already-classified Forgejo-era coordination health, status-update,
roadmap, and cluster-services seal/closeout snapshots. Git history and #1586
retain the exact path lineage; current repo docs must not cite those deleted
snapshots as authority.

#952 must remain open until #1015 through #1025 are closed and a current guard
run or equivalent source inspection shows no remaining blocking live-doc drift
for this issue family.

## Classified Authority Slices

### Retired Coordination Snapshot Deletions (TFR-019 / #1586)

Issue #1586 deleted the already-classified Forgejo-era coordination health,
status-update, and roadmap snapshot files that had been covered by #1164,
#1165, #1174, #1232, #1233, #1234, #1236, and #1238. Their historical
classification evidence remains in git history and the closed issues; this
register intentionally does not keep live per-file rows for deleted documents.
Current coordination authority remains GitHub issue and pull-request state plus
the active repo documentation entry points.

### Request Contract Authority (TFR-019 / #1136)

Classified for TFR-019 / GitHub issue #1136 on 2026-06-25 after reviewing this
register's authority rule and review method, `docs/REQUEST_CONTRACT.md`,
`docs/INDEX.md`, the verification/model references in
`docs/NEXTGEN_VERIFICATION_EVIDENCE_CHAIN_AUTHORITY.md`,
`docs/NEXTGEN_VERIFICATION_CONTRACT_ROADMAP.md`,
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
| `docs/CHECKSUM_ARCHITECTURE_DESIGN.md` | Historical input | Imported G3 design target and old closeout text. Current source has object-store integrity pieces, but `validation/claims.toml` has no validated production checksum, repair, erasure, or committed-root tamper-detection claim covering the full architecture. |
| `docs/design/1683-checksum-architecture-g3-pillar-design-spec.md` | Historical input | Duplicate imported G3 design target with implementation deferred to wire-up issues. It must not be cited as current TideFS checksum status. |
| `docs/design/end-to-end-checksum-architecture-g3-pillar.md` | Historical input | Imported canonical-design wording remains useful as target architecture, but its mandatory end-to-end, scrub, repair, erasure, and chain-of-trust claims exceed current claim-registry evidence. |
| `docs/security/blake3-integrity-boundary.md` | Historical input | Imported release-train closeout note. It may inform review of residual BLAKE3 overfit, but its conformant-crate and closeout language is not current release authority. |

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
| `docs/UAPI_ABI_BOUNDARY_OW202.md` | Historical input | Tracker-era duplicate with the retired `tidefs-schema-codec-vfs-boundary` crate path and old mirror-layout table. It may inform preview layout review, but it is not current UAPI/ABI authority and must not be cited as a production Linux ioctl/statx/ublk or kernel module ABI freeze. |
| `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md` | Current spec | Target architecture and evidence-tier map for kernel-resident pool-engine work. Current implementation evidence is the narrow Linux 7.0 QEMU configured-pool smoke described in `docs/GITHUB_CI.md`; full-kernel, daemonless storage parity, xfstests, crash/replay, object/extent engine, block-volume export, and production-readiness claims remain outside this status. |
| `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md` | Current policy | Binding only as the Linux 7.0 kernel development workflow: external-module or Linux-branch ownership, out-of-repo build output, disposable QEMU guests, and Nix/QEMU acceptance gates. It is not runtime maturity evidence and does not require broad kernel validation for documentation-only slices. |
| `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md` | Current spec | Binding only for kernel-family rollout order, first-seam scope, and anti-regression constraints. It does not prove current full-kernel residency, no-daemon parity, block-volume behavior, xfstests coverage, crash recovery, distributed behavior, or production readiness. |
| `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md` | Current spec | Binding only for the source-level locking, RCU, pin, workqueue, and acceptance-row model that later kernel work must consume. It is not a kernel implementation gate and not runtime proof until issue-scoped Kbuild/QEMU/fault evidence maps to the rows. |

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
| `docs/DESIGN_OVERFITTING_POLICY.md` | Historical input | Imported design-policy with a 2026-05-18 reconciliation note stating sections are superseded by P1-01 and workspace-package-classification. Binding rules (error variants, feature flags, dynamic dispatch, concurrency, unsafe) remain useful guidance, but the document references Forgejo state and partially-superseded crate-removal directives. |
| `docs/MODULE_OWNERS_INVARIANTS_PC002.md` | Delete candidate | Scaffold document with an empty ownership table and no live owner-path bindings. The referenced `tidefs-xtask check-module-owners` gate has no data to verify. |
| `docs/ON_DISK_FORMAT_VERSIONING_AND_COMPATIBILITY_POLICY.md` | Historical input | Imported release-policy with well-articulated format versioning discipline, but references a stale Forgejo issue (#6518) and non-existent sub-documents (FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md, TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md, ZERO_COPY_DMA_PINNING_PAGE_LOAN_LAW_P4-04.md). The pre-release note correctly states no public release has shipped. |
| `docs/RDMA_TRANSPORT_POSITION.md` | Historical input | Imported transport-position document referencing non-existent sub-documents and stating "TideFS does not have a product RDMA data path yet." Useful for future RDMA design reference. |
| `docs/DISTRIBUTED_OPERATOR_PRODUCT_SURFACE_BLOCKER_MAP_OW307D.md` | Historical input | Imported OW-307D blocker map. Records typed truth rows and deterministic demo rows present in source, but the parent OW-307 gate remains open and a runtime-fed operator product surface is not yet present. |
| `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md` | Current policy | Design decision #1267 recording the current runtime-fed operator product-surface boundary after the OW-307D blocker map. States that no runtime-fed operator product surface exists, the P10-04 truth-surface law is missing from the repository, and no product carrier class is selectable until prerequisite gates (TFR-011, TFR-017) close. Includes follow-up issue map for P10-04 disposition, TFR-011/TFR-017 closeout, and documentation cleanup. |
| `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` | Missing | Truth-surface law reference absent from the repository. Issue #1270 records the gap: the law expected to define mandatory surface classes, provenance/exactness/freshness rendering, carrier verification, and the `truth_view` concept does not exist, so citations to this path are not current authority. |
| `docs/PREVIEW_USER_MANUAL.md` | Historical input | Imported preview manual that correctly disclaims production readiness and references the claims gate and transform authority. Preview commands are useful orientation but the document is preview-scoped, not binding policy. |
| `docs/troubleshooting-build.md` | Historical input | Imported developer guide for build failure diagnosis covering Nix shell and Cargo issues. Useful reference but specific tool versions and paths may have drifted since import. |

**Architecture, design, and feature docs**

| Path | State | Classification note |
|---|---|---|
| `docs/HUMAN_TERMINOLOGY.md` | Historical input | Imported naming authority mapping human architecture names to Rust paths. Some listed crate paths (e.g. `tidefs-types-control-plane-core`) do not exist in the current workspace; several families are marked "Future". The naming pattern is useful reference but not current source authority. |
| `docs/VFS_ENGINE_API_CONTRACT.md` | Historical input | Imported implemented-source contract for the VFS Engine API. References stale Forgejo issues (#1887, #1213). The canonical types and operations are useful design reference, but full source-behavior alignment verification is too large for this slice. |
| `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md` | Historical input | Imported production-design FUSE binding strategy describing the `fuser`-based binding, capability negotiation, and feature matrix. Useful reference, but full per-capability source alignment verification is too large for this slice. |
| `docs/FUSE_OPERATION_COVERAGE_MATRIX.md` | Historical input | Imported design-spec FUSE operation coverage matrix with op-by-op semantics, errno contracts, and coherency profiles. Useful implementation reference at design maturity. |
| `docs/DEBUGGING_WORKFLOWS.md` | Historical input | Imported developer guide covering debug builds, tracing, test isolation, and xtask checks. Generally applicable commands, but specific references may have drifted. |
| `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md` | Historical input | Imported design charter for block volume projection. Detailed authoritative/projection noun mapping and durability classes. References Forgejo state and design-consolidation phase language. |
| `docs/DATASET_FEATURE_FLAGS_DESIGN.md` | Historical input | Imported design-spec for per-dataset feature flags with three compatibility classes. References Forgejo issue #1223. |
| `docs/DATASET_LIFECYCLE_DESIGN.md` | Historical input | Imported design-spec for dataset lifecycle state machine. References Forgejo issue #1219. Claims registry has no validated dataset-lifecycle claim. |
| `docs/TXG_STATE_MACHINE_DESIGN.md` | Historical input | Imported spec-draft for canonical commit ordering and multi-phase commit_group state machine. References Forgejo issue #1267. |
| `docs/SPACEMAP_ALLOCATOR_DESIGN.md` | Historical input | Imported design-spec for spacemap and segment allocator. Explicitly states no runtime allocator or persistent spacemap exists in current source. References Forgejo issue #1189. |
| `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md` | Historical input | Imported design-spec for logical vs physical space accounting. References Forgejo issue #1215. Claims registry has no validated space-accounting claim. |
| `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` | Historical input | Imported design-spec for pool labels, import/export, and device topology. References Forgejo issue #1254. |
| `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md` | Historical input | Imported design-spec that self-declares it has been superseded by `docs/design/device-layout-policies-adaptive-segment-sizing.md`. References Forgejo issue #1193. |
| `docs/DEFERRED_CLEANUP_WORK_QUEUES_DESIGN.md` | Historical input | Imported design-spec for bounded-memory deferred cleanup work queues. References Forgejo issue #1212. |
| `docs/DETERMINISTIC_TRACE_ORACLE_DESIGN.md` | Historical input | Imported design-spec for deterministic trace oracle. References Forgejo issue #1174. |
| `docs/CLUSTER_TRANSPORT_BOUNDEDNESS_DESIGN.md` | Historical input | Imported design-spec for bounded cluster transport. References Forgejo issue #1210. Claims registry has no validated distributed-transport claim. |
| `docs/INTENT_LOG_SYNC_WRITE_LATENCY_PC008.md` | Historical input | Imported implemented-source specification for intent-log sync write latency (PC-008). Binds PC-008 closeout to source without claiming production persistent WAL or measured SLO pass. |
| `docs/TRANSACTION_COMMIT_GROUPS_PC007.md` | Historical input | Imported implemented-source specification for transaction commit groups (PC-007). Binds existing Local Filesystem transaction-root implementation and FUSE fsync boundary. |
| `docs/MEMBERSHIP_SERVICE_DESIGN.md` | Historical input | Imported design-spec for cluster membership service. References Forgejo issue #1209. ZFS/Ceph comparison text is design input only and is not a cluster-membership, distributed-availability, scale, performance, or successor claim. Claims registry has no validated cluster-membership claim. |
| `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md` | Historical input | Imported design-spec for distributed extent redundancy with ShardGroupV1 encoding. References Forgejo issue #1286. ZFS/Ceph comparison text is design input only and is not a write-latency, write-amplification, durability, cost, or successor claim. |
| `docs/SCRUB_REPAIR_RESILVER_DESIGN.md` | Historical input | Imported design-spec for background integrity services. References Forgejo issue #1288. Claims registry has only planned/blocked scrub claims. |
| `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` | Historical input | Imported design-spec superseded by the G4 pillar at `docs/design/production-erasure-coding-crush-placement-g4-pillar.md`. References Forgejo issue #1249. |
| `docs/design/openzfs-ceph-successor-claim.md` | Historical input | Imported sealed design-spec for the OpenZFS/Ceph successor claim with 8-dimension quantitative comparison. The seal is historical, not current claim authority. Claims gate currently blocks publishing an OpenZFS/Ceph successor claim; any future retained product-facing statement needs a #875 claim id and #928/#930 comparator evidence. |
| `docs/design/production-erasure-coding-crush-placement-g4-pillar.md` | Historical input | Imported G4 pillar design-spec for TideCRUSH deterministic placement. References Forgejo issue #1779. Supersedes earlier erasure-coding placement designs. |
| `docs/design/compression-design-strategy.md` | Historical input | Imported design-spec for compression format extension model. References Forgejo issue #1245. Transform authority blocks mounted compression claims. |
| `docs/design/2159-milestone-targets-velocity-update.md` | Historical input | Imported milestone-target architecture with May 2026 velocity assessment. Supersedes prior milestone targets. Useful coordination reference. |

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
| `docs/ARCHITECTURE.md` | Current spec | Binding only as the high-level workspace layer map and harness/product separation reference. It is not evidence that every listed crate is complete, kernel-bound, production-ready, or validated by runtime CI. |
| `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md` | Historical input | Imported OW-005/OW-014 implementation note already marked as review material. Record-version and trailer details may inform source review, but the file is not current format authority until reconciled with live source and claims evidence. |
| `docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md` | Historical input | Imported OW-004 recovery theorem and failure model. Useful target framing, but not a current production no-fsck guarantee or crash-recovery claim without matching runtime evidence. |
| `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md` | Historical input | Broad production-depth baseline law with old blueprint-style cross-references. The scoped kernel workflow/spec rows above are the current authority for Linux 7.0 development and rollout behavior. |
| `docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md` | Historical input | Imported std/no_std boundary law for future kernel/userspace split. It remains design input until checked against the current workspace package graph and kernel-family source boundaries. |
| `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md` | Historical input | Imported Rust-for-Linux crate-boundary target. Current scoped kernel rollout authority lives in the P7-01/P7-03/P7-05 rows above; this file does not prove implemented Rust-for-Linux leaf-module readiness. |
| `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md` | Historical input | Imported UAPI/FFI schema law. The current preview UAPI authority is `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`; this broader file is not current ABI/FFI freeze authority. |
| `docs/LOCK_HIERARCHY_AND_CONCURRENCY_MODEL.md` | Historical input | Imported lock hierarchy target for storage, FUSE, ublk, and future cluster VFS RPC. It needs a source audit before it can supersede the scoped kernel locking row above. |

**Block-volume adapter and ublk source-boundary docs**

| Path | State | Classification note |
|---|---|---|
| `docs/BLOCK_VOLUME_ADAPTER_CORE_OW301A.md` | Current spec | Scoped current spec for the executable block-volume core model in `tidefs-block-volume-adapter-core`: geometry bounds, exact read/write image behavior, dirty epochs, flush barriers, discard/zero behavior, and refusal records. It is not userspace daemon or Linux block-device readiness evidence. |
| `docs/BLOCK_VOLUME_QUEUE_ADMISSION_OW301B.md` | Current spec | Scoped current spec for queue/admission records in `tidefs-block-volume-adapter-core`. It binds deterministic admission mirrors, not full ublk runtime or fio/blktests acceptance. |
| `docs/BLOCK_VOLUME_DISPATCH_EXECUTION_OW301C.md` | Current spec | Scoped current spec for dispatch/completion execution over admitted block-volume submissions in `tidefs-block-volume-adapter-core`. It does not claim production export lifecycle coverage beyond the model. |
| `docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md` | Current spec | Scoped current spec for modeled export phases in the block-volume adapter core. It is not evidence of a live Linux block export. |
| `docs/BLOCK_VOLUME_CACHE_COHERENCY_OW301E.md` | Current spec | Scoped current spec for clean-cache windows, dirty-range epochs, flush/FUA barriers, and cache-loss records in the block-volume model. Cached bytes remain non-authoritative. |
| `docs/BLOCK_VOLUME_RESIZE_FENCE_OW301F.md` | Current spec | Scoped current spec for modeled resize target, tail-range, quiesce, and fence records. It does not prove live failover or kernel device resize behavior. |
| `docs/BLOCK_VOLUME_ADAPTER_HOST_PREFLIGHT_OW301H.md` | Current spec | Scoped current spec for the daemon host preflight command and non-mutating Linux ublk readiness signals. It does not admit mutating ublk control operations by itself. |
| `docs/BLOCK_VOLUME_UBLK_ABI_CONTROL_PLAN_OW301I.md` | Current spec | Scoped current spec for typed Linux ublk ABI command/record planning in `crates/tidefs-ublk-abi` and the daemon plan surface. It is not a live-device export claim. |
| `docs/BLOCK_VOLUME_FILE_BACKING_OW301N.md` | Current spec | Scoped current spec for file-backed block image behavior exposed by `BlockVolumeFileImage` and the daemon backing-file smoke command. It does not claim kernel ublk device service. |
| `docs/BLOCK_VOLUME_UBLK_CONTROL_OPEN_OW301O.md` | Current spec | Scoped current spec for real-host `/dev/ublk-control` open admission and refusal records. It is an admission boundary, not a full export guarantee. |
| `docs/BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_OW301P.md` | Current spec | Scoped current spec for the read-only `UBLK_U_CMD_GET_FEATURES` uring command probe. It does not authorize mutating control commands. |
| `docs/BLOCK_VOLUME_UBLK_ADD_DEV_BOUNDARY_OW301Q.md` | Current spec | Scoped current spec for guarded `UBLK_U_CMD_ADD_DEV` submission after host-open and read-only probe admission. It is not proof of sustained data-queue service. |
| `docs/BLOCK_VOLUME_UBLK_DEL_DEV_CLEANUP_BOUNDARY_OW301R.md` | Current spec | Scoped current spec for guarded ADD_DEV then DEL_DEV cleanup behavior. It covers cleanup admission only, not production export lifecycle closure. |
| `docs/BLOCK_VOLUME_UBLK_SET_PARAMS_BOUNDARY_OW301S.md` | Current spec | Scoped current spec for guarded `UBLK_U_CMD_SET_PARAMS` projection over the concrete device id returned by ADD_DEV. It does not prove guest-visible filesystem behavior. |
| `docs/BLOCK_VOLUME_UBLK_START_DEV_BOUNDARY_OW301T.md` | Current spec | Scoped current spec for guarded `UBLK_U_CMD_START_DEV` command shape and concrete-device admission. It does not claim mounted block workload acceptance. |
| `docs/BLOCK_VOLUME_UBLK_FETCH_REQ_READINESS_BOUNDARY_OW301U.md` | Current spec | Scoped current spec for data-queue `UBLK_U_IO_FETCH_REQ` command shape, queue id, and SQE128 readiness records. It is readiness authority, not live request throughput evidence. |
| `docs/BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_BOUNDARY_OW301V.md` | Current spec | Scoped current spec for guarded `/dev/ublkcN` data-queue runtime-open ownership after ADD_DEV. It does not prove request servicing. |
| `docs/BLOCK_VOLUME_UBLK_FETCH_REQ_SUBMISSION_BOUNDARY_OW301W.md` | Current spec | Scoped current spec for first guarded `FETCH_REQ` submissions after control and data-queue admission. It does not claim full data-plane completion behavior. |
| `docs/BLOCK_VOLUME_UBLK_COMMIT_FETCH_BOUNDARY_OW301X.md` | Current spec | Scoped current spec for guarded `COMMIT_AND_FETCH_REQ` submission after caller-completed fetched requests. It is not a broad block-volume crash-consistency claim. |
| `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md` | Current spec | Scoped current spec for the started-export admission artifact and fail-closed verification path. It does not close broader block-volume runtime validation. |
| `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md` | Historical input | Imported production-depth ublk queue topology law. The scoped OW-301 rows above are the current authority for implemented slices; this broader topology remains design input. |
| `docs/EXPORT_FENCING_RESIZE_FAILOVER_RUNTIME_P6-03.md` | Historical input | Imported production-depth export fencing, resize, and failover runtime target. The OW-301 lifecycle/cache/resize rows are scoped model authority only and do not validate this full runtime. |
| `docs/BLOCK_ACCEPTANCE_STRESS_HARNESS_MATRIX_P6-04.md` | Historical input | Imported block acceptance and stress harness matrix. It is a validation target, not current evidence that fio, blktests, guest filesystems, or kernel block exports pass. |

**FUSE/POSIX adapter docs**

| Path | State | Classification note |
|---|---|---|
| `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` | Current policy | Binding only as the adapter-boundary guardrail that prevents runtime FUSE handlers from bypassing the TideFS request/VfsEngine path into storage mutation authority. It does not close xfstests rows or broader POSIX/FUSE completeness. |
| `docs/FUSE_LSEEK_PC004B.md` | Current spec | Scoped current spec for the non-release dense-file preview `lseek` behavior described in the file. It does not claim sparse-file fidelity or parent POSIX-complete FUSE closure. |
| `docs/design/clustered-posix-lock-forwarding-boundary.md` | Current spec | Scoped current spec for the clustered POSIX mounted LOCK forwarding boundary decided by GitHub issue #626. It names the future mounted owner for `LockServiceHandle` construction and follow-up issue split, but it is not implementation evidence that clustered POSIX mounts exist today. |
| `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md` | Historical input | Imported production-depth FUSE worker/queue model. Useful design input, but it must not be cited as current runtime proof for queues, interrupts, forget handling, page runtime, or kernel parity. |
| `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md` | Historical input | Imported production-depth POSIX adapter topology. It contains useful residency and topology framing, but current FUSE runtime authority is issue-scoped evidence rather than this broad ledger. |
| `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md` | Historical input | Imported page-cache, writeback, and mmap design target. It is not current proof of writeback, mmap coherency, direct-I/O, or no-daemon behavior. |
| `docs/POSIX_SUBSET.md` | Historical input | Imported OW-104/OW-106/OW-107 implementation note already marked as TFR-019 review material. It can inform POSIX subset audits but is not current mounted-runtime authority. |
| `docs/POSIX_SEMANTICS_OW106.md` | Historical input | Imported OW-106 userspace FUSE preview note. It documents historical semantic targets and must not be cited as current POSIX/FUSE runtime closure. |

**Operator, placement, and distributed-runtime docs**

| Path | State | Classification note |
|---|---|---|
| `docs/OPERATOR_MANUAL_DYNAMIC_TUNING_AND_REALTIME_OBSERVABILITY.md` | Historical input | Imported operator manual for dynamic tuning and observability. It remains useful target material, but a runtime-fed operator product surface is not established by this file. |
| `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md` | Historical input | Imported production-depth policy-authority runtime-surface design. It is not current authority for a complete kernel-hosted or runtime-fed policy authority service. |
| `docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md` | Historical input | Imported publication-pipeline runtime decomposition. Useful queue/batch/commit vocabulary, but not current evidence of the full production publication pipeline. |
| `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md` | Historical input | Imported receipt/response runtime-emission design. It is not current closure for the local/distributed receipt authority or response-envelope runtime surface. |
| `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` | Current spec | Design authority for the native storage-intent policy surface introduced by GitHub issue #839: guarantee/ack classes, receipt-satisfaction predicates, satisfaction reconciliation, proximity domains, workload prediction, media roles, flash-wear cost, RAM authority classes, relocation/defrag policy, operator receipt explanation, and the need for the #863 storage-intent fault-validation matrix. It is not runtime implementation evidence, a POSIX sync validation claim, a distributed availability claim, a completed fault-validation claim, or a performance superiority claim. |
| `docs/STORAGE_INTENT_SERVICE_OBJECTIVE_DESIGN.md` | Current spec | Scoped current spec for GitHub issue #915 service-objective evidence: objective identity, workload and operation scope, latency percentile/tail, throughput/burst/dwell, topology/media/proximity, RPO/RTO, isolation, capacity, cost, wear, decision/action, measurement, comparator, claim, and typed refusal requirements. It is not runtime implementation evidence, a performance-validation artifact, or a superiority claim over OpenZFS, Ceph, DRBD, or any other system. |
| `docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md` | Current spec | Scoped current spec for GitHub issue #920 result/refusal evidence: caller-visible outcome identity, policy/query/decision/receipt refs, degraded-visible state, service-objective/admission/action blockers, response-registry projection, retryability, caller compression, and retention/audit requirements. It is not runtime implementation evidence, a response-registry runtime, a POSIX errno validation artifact, or a product-readiness claim. |
| `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md` | Historical input | Imported production-depth timing and drift law. It needs source and runtime-evidence reconciliation before it can govern distributed timing behavior. |
| `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md` | Historical input | Imported production-depth membership, placement, and failure-domain model. It remains design input until distributed membership and placement claims have runtime evidence. |
| `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md` | Current spec | Scoped current spec for deterministic joint quorum-set identity in `crates/tidefs-membership-epoch`. It does not validate a full cluster-membership service. |
| `docs/ERASURE_CODED_LAYOUT_OW306.md` | Current spec | Scoped current spec for the deterministic single-parity erasure layout model in `crates/tidefs-replication-model`. It is not production erasure-coding placement or rebuild evidence. |
| `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` | Current spec | Scoped current spec for pool-wide placement contract and property-tested local model behavior. It does not prove distributed availability, rebake, recovery, or operator lifecycle behavior. |
| `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` | Current spec | Scoped current spec for the issue #18 placement receipt authority split, including the shared `PlacementReceiptRef` policy-satisfying gate and remaining follow-up issues #674, #675, and #676. It is not a closure claim for distributed availability, rebuild, rebake, reclaim, or runtime validation. |
| `docs/RAM_AUTHORITY_DESIGN.md` | Current spec | Scoped current spec for the issue #847 RAM authority boundary: `ram-volatile-local`, `ram-volatile-replicated`, `ram-intent-backed`, and `pmem-durable` semantics, receipts, failure behavior, policy-transition rules, resource-governor boundaries, and operator explanation requirements. It is not runtime implementation, PMem platform validation, distributed quorum proof, or POSIX durability evidence. |
| `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` | Historical input | Imported production-depth replication, rebuild, and relocation flow design. It is not current runtime proof for anti-entropy, repair rebuild, relocation, failover, or cutover drains. |

## Incumbent Comparison Audit Slice (#931)

This initial #931 slice classifies the following legacy incumbent-comparison
sections as historical design lessons or fail-closed review blockers, not
current TideFS product evidence. None of these documents may be cited for a
current OpenZFS, ZFS, Ceph, DRBD, ext4/XFS, performance-superiority,
cost-effectiveness, flash-wear, RAM, WAN, durability, or successor claim
unless the cited statement is re-expressed through a #875 claim id and the
comparator evidence required by #928/#930:

- `docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md`: ZFS/ext4/CephFS orphan-index
  table and former "key advantages" list are non-claim design lessons.
- `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`: ZFS ZAP comparison and former
  "improvements over ZFS" list are non-claim design lessons.
- `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md`: ZFS/Ceph extent-layout tables,
  random-read cost hypothesis, and design-mistake coverage are non-claim
  design lessons.
- `docs/MEMBERSHIP_SERVICE_DESIGN.md`: ZFS/Ceph cluster-membership comparison
  is design input only; no cluster-membership claim is validated.
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`: ZFS/Ceph deferred-redundancy
  and write-amplification comparison is design input only.
- `docs/ONLINE_DEFRAG_BPR_DESIGN.md`: ZFS/Ceph defrag and BPR comparison text
  is target mechanism input, not evidence of implemented online defrag; its
  BPR mechanism is subordinate to #848 storage-intent relocation gates, #844/#856
  cost and wear evidence, #845 prediction/payback evidence, and #904 media
  capability evidence.
- `docs/design/openzfs-ceph-successor-claim.md`: the sealed successor claim is
  historical input, not current claim authority.
- `docs/WHOLE_REPO_REVIEW.md`: incumbent references are fail-closed review
  blockers only.

Non-overlapping child slices completed the cluster-by-cluster audit and added
Incumbent Comparison Boundary sections to the following file groups. Each
grouped file is classified as historical/design input only for its comparison
text; no product-facing successor, superiority, or parity wording exists in
any of these files without a #875 claim id and #928/#930 comparator evidence.

Child slices (all merged):
- #933 / PR #955: background jobs, deferred cleanup, reclaim, orphan-index,
  and universal-cursor comparison wording.
- #934 / PR #956: dataset lifecycle, snapshot, send/receive, pool import/export,
  device topology, rename, reflink/copy-offload, and operator lifecycle
  comparison wording.
- #935 / PR #946: cache, mmap, RAM authority, sync intent, latency/throughput,
  QoS, and access-pattern comparison wording.
- #936 / PR #937: integrity, checksum, transform, scrub/repair, erasure-coding,
  SOTA, and coverage-matrix comparison wording.
- #965: online defrag BPR subordinate to storage-intent relocation gates.

Consolidation closure (this commit):
- `docs/ARCHITECTURE.md`: ZFS and CephFS "Where TideFS is ahead" / "gaps to
  close" comparison sections are historical design input, not current capability
  or successor claims. A Incumbent Comparison Boundary section now gates both
  comparison blocks, and the former "CephFS successor claims" product-surface
  line is rewritten as a non-claim scope note citing #875/#928/#930.

This consolidation closes the #931 audit. No live doc contains un-gated
incumbent-comparison, successor, or product-superiority wording. Any future
product-facing comparison must route through #875 claim ids and #928/#930
comparator evidence.

## Initial Open Queue Resolution (#689)

Classified for TFR-019 / GitHub issue #689 on 2026-06-21 after reviewing the
register method, `docs/WHOLE_REPO_REVIEW.md`, `validation/claims.toml`, and
bounded source search for the tempting implementation references. This slice
does not promote any initial-queue document to current policy or current spec:
the documents below carry old Forgejo issue-closeout, sealed-design, maturity,
or production-depth wording whose full source and claims-gate reconciliation is
larger than this documentation-authority cleanup.

| Path | State | Classification note |
|---|---|---|
| `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` | Historical input | Imported Forgejo #1285 design with on-media extent/locator authority wording. Live source has extent-map and locator-table crates, but this slice did not reconcile the full V2 media model, migration text, and claims-gate surface, so it is design input only. |
| `docs/GENERATION_STALENESS_DISCIPLINE_DESIGN.md` | Historical input | Imported Forgejo #1242 stale-generation/fence model that spans caches, commit groups, metadata, replication, and jobs. It needs a dedicated source and claims review before it can govern current staleness behavior. |
| `docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md` | Historical input | Imported Forgejo #1290 xattr storage design with proposed on-media records and ACL integration. Current xattr/ACL behavior and claims coverage were not audited here, so the document remains review material. |
| `docs/POSIX_ACL_XATTR_CODEC_DESIGN.md` | Historical input | Imported ACL codec design that marks itself superseded and names a replacement issue lineage. It must not be cited as current POSIX ACL authority without a fresh ACL/xattr source review. |
| `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` | Historical input | Imported Forgejo #1180 refcount-delta reclamation design. Current reclaim/deadlist work is active elsewhere, but the complete queue data model and runtime evidence were not validated in this slice. |
| `docs/SEMANTIC_OP_CANONICAL_NAME_REGISTRY_DESIGN.md` | Historical input | Imported Forgejo #1200 semantic-op registry proposal. It describes a central naming authority broader than the current claims reviewed here and remains implementation-planning input. |
| `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md` | Historical input | Imported snapshot deadlist/pinning design that reaches into reclamation, references, and snapshot lifecycle. It needs a dedicated snapshot/deadlist source and claims-gate review before promotion. |
| `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md` | Historical input | Imported resource-governor design with broad scheduling and budget claims. Open resource-governor implementation work is separate; this document is not current runtime authority. |
| `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md` | Historical input | Imported universal cursor framework design across scrub, send/receive, rebake, resilver, and cleanup jobs. Promotion would require cross-crate source and evidence review beyond this slice. |
| `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` | Historical input | Imported design-sealed tristate extent model that claims implemented source coverage. Although bounded search found current extent-map crates, the old authority and phase wording exceed the reviewed claims surface. |
| `docs/design/1781-shard-groups-replicas-rebake-design-spec.md` | Historical input | Imported shard-group/rebake design iteration. It is useful lineage for distributed layout planning, not current redundancy, rebake, or recovery evidence. |
| `docs/design/1782-shard-groups-replicas-rebake-design-spec.md` | Historical input | Imported shard-group/rebake design iteration with old issue lineage. It remains historical comparison input until a distributed placement/rebake source audit promotes a narrower contract. |
| `docs/design/1806-shard-groups-replicas-rebake-design-spec.md` | Historical input | Imported shard-group/rebake design iteration. It must not be cited as current distributed-storage behavior or runtime validation. |
| `docs/design/2068-shard-groups-replicas-rebake-pathway-design.md` | Historical input | Imported rebake-pathway refinement whose production-depth flow claims exceed the current validation register. It remains design input for future rebake authority work. |
| `docs/design/METADATA_ENGINE_PARALLELISM_DESIGN.md` | Historical input | Imported metadata-engine parallelism design with broad scheduling and correctness implications. It needs dedicated engine/source review before any current-spec promotion. |
| `docs/design/background-service-framework-canonical-consolidation.md` | Historical input | Imported background-service consolidation note in a larger duplicate lineage. Current `tidefs-background-scheduler` source exists, but this closeout/consolidation document was not reconciled with live scheduler authority. |
| `docs/design/background-service-framework-design-1803.md` | Historical input | Imported background-service design iteration. It remains lineage material for scheduler review and is not current service-contract authority. |
| `docs/design/background-service-framework-design-enhanced.md` | Historical input | Imported enhanced background-service design. Current scheduler behavior and claims evidence were not audited against the enhancement set in this slice. |
| `docs/design/background-service-framework-design-spec.md` | Historical input | Imported background-service design-spec variant. It is not authoritative over the current scheduler without a focused `tidefs-background-scheduler` source and claims review. |
| `docs/design/background-service-framework-design.md` | Historical input | Imported background-service framework design referenced by multiple old distributed-service docs. It remains useful design context, not current runtime authority. |
| `docs/design/background-service-framework-multithread-design.md` | Historical input | Imported multithreaded background-service design. It must be reconciled with current scheduler source and validation before being used as a current concurrency contract. |
| `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md` | Historical input | Imported phase-tracking note for background-service wire-up. It remains historical input until live source and validation are checked against the phase claims. |
| `docs/design/bounded-cluster-membership-state.md` | Historical input | Imported bounded-membership state design. Current distributed membership authority is only whatever later scoped rows classify; this file is not current cluster-service evidence. |
| `docs/design/deterministic-trace-oracle-system.md` | Historical input | Imported deterministic trace-oracle design. It may inform future validation tooling, but this slice did not promote any trace-oracle claim or scanned claims-gate surface. |
| `docs/design/device-layout-policies-adaptive-segment-sizing.md` | Historical input | Imported adaptive segment-sizing/device-layout policy design. It needs storage allocator/device-layout source and evidence review before it can constrain current behavior. |
| `docs/design/directory-change-streams-namespace-event-protocol.md` | Historical input | Imported directory change-stream protocol design. Current namespace event behavior and claims coverage were not audited here, so it remains design input. |
| `docs/design/incremental-job-core-trait-checkpoint-codec-design.md` | Historical input | Imported incremental-job trait/checkpoint design. Live incremental-job crates exist, but this broad codec and job-contract document needs focused source review before promotion. |
| `docs/design/polymorphic-extent-maps-design.md` | Historical input | Imported lowercase polymorphic-extent-map design duplicate/variant. It remains lineage material alongside the already historical extent-map comparison docs. |
| `docs/design/prefetch-readahead-budgeted-speculative-io.md` | Historical input | Imported prefetch/readahead design with performance and scheduling implications. No current performance or runtime evidence was promoted in this slice. |
| `docs/design/rebake-architecture-ingest-journal-to-base-shard-conversion.md` | Historical input | Imported rebake architecture document for ingest-journal to base-shard conversion. It is future distributed-layout input, not current rebake authority. |
| `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md` | Historical input | Imported lowercase refcount-delta cleanup design duplicate/variant. It is review material until reclamation source and claims evidence are reconciled. |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design-1952.md` | Historical input | Imported scrub/repair/resilver orchestration iteration. `validation/claims.toml` still blocks scrub/read isolation and scrub runtime queues, so this cannot be current integrity-service authority. |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design-1965.md` | Historical input | Imported scrub/repair/resilver orchestration iteration. Its distributed repair and resilver claims exceed current claim-registry evidence. |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md` | Historical input | Imported broad integrity-service orchestration design. It remains historical input until scrub, deep-scrub, repair, and resilver source behavior and runtime evidence are reviewed together. |
| `docs/design/scrub-deep-scrub-repair-resilver-orchestration-placement-ae-auditor.md` | Historical input | Imported placement/anti-entropy auditor refinement for scrub and repair. It is not current placement or anti-entropy authority without a dedicated implementation/evidence review. |
| `docs/design/shard-groups-replicas-rebake-design-1963.md` | Historical input | Imported shard-group/rebake design iteration. It remains distributed-storage lineage material and not current runtime behavior. |
| `docs/design/shard-groups-replicas-rebake-design-spec.md` | Historical input | Imported sealed shard-group/rebake design-spec with multiple prior-iteration links. It must not be used as current distributed redundancy or rebake evidence. |
| `docs/design/v1-extent-map-tristate-model.md` | Historical input | Imported sealed architecture/design note for the V1 tristate extent model. It references current extent-map crates, but source/claims reconciliation for the full sparse-file, FIEMAP, fallocate, and stat-block contract remains out of scope here. |
| `docs/design/v1-locator-table-inline-hash.md` | Historical input | Imported V1 locator-table inline-hash design that names `crates/tidefs-locator-table`. Promotion would require a focused locator-table source, validation, and claims-gate review. |
| `docs/design/workload-adaptive-recordsize-and-extent-shaping.md` | Historical input | Imported workload-adaptive recordsize/extent-shaping design. It contains policy and performance implications that need storage allocator, extent, and claims evidence before becoming current authority. |

### Background Service Framework Scheduler Authority (TFR-019 / #1537)

Classified for TFR-019 / GitHub issue #1537 on 2026-06-29 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, `docs/WHOLE_REPO_REVIEW.md`, the root
background-service redirect, every tracked
`docs/design/background-service-framework-*.md` file, live scheduler source in
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

The checked claims surface does not validate broader runtime or product wording.
`validation/claims.toml` and generated `docs/CLAIM_REGISTRY.md` still keep
`scheduler.dirty_debt.no_hidden.v1` blocked, scrub foreground-read protection
planned, and storage-intent successor/comparator wording blocked. This slice
therefore does not claim production scheduler readiness, no-hidden-queue
closure, FUSE-loop integration, lower latency, stronger crash recovery, operator
visibility, release readiness, or superiority over OpenZFS, Ceph, DRBD, or local
filesystems. Forgejo issue closeout, `Maturity:` status, phase-completion,
implementation-status, multi-threaded-runtime, and product-comparison wording in
the files below remain historical lineage only.

Future promotion beyond the source API must be split by non-overlapping write
sets: scheduler API/reference wording belongs to the scheduler crate or a new
focused scheduler-authority doc; FUSE-loop integration belongs to the POSIX/FUSE
runtime paths; no-hidden-queue and foreground-read claims belong to
`validation/claims.toml` plus validation artifacts; multi-threaded runtime
claims belong to `crates/tidefs-background-scheduler/src/multi_threaded.rs` plus
focused runtime evidence; product-comparison claims remain under the #875
claim/comparator evidence path.

| Path | State | Classification note |
|---|---|---|
| `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` | Historical input | Redirect into the imported background-service design lineage. It now points readers at this register boundary; it is not current scheduler/runtime authority, phase-completion evidence, FUSE-loop proof, no-hidden-queue proof, release readiness, or product-comparison permission. |
| `docs/design/background-service-framework-canonical-consolidation.md` | Historical input | Imported Forgejo-era consolidation note. It remains lineage for background-service review, but its design-spec and consolidation-status wording does not override the live `tidefs-background-scheduler` source contract or current claims gate. |
| `docs/design/background-service-framework-design-1803.md` | Historical input | Imported background-service design iteration. It is useful design context for the scheduler trait/priority/budget review but is not current service-contract authority. |
| `docs/design/background-service-framework-design-1962.md` | Historical input | Imported self-contained background-service design summary that points at the old Forgejo consolidation lineage. It was not previously classified in the #689 table; this slice preserves it as historical input, not current architecture, runtime, or product-status authority. |
| `docs/design/background-service-framework-design-enhanced.md` | Historical input | Imported enhanced design variant. Source review in this slice does not validate its lifecycle, starvation, backpressure, observability, or implementation-status claims, so it remains review material. |
| `docs/design/background-service-framework-design-spec.md` | Historical input | Imported design-spec/roadmap variant. The live scheduler source supports only the narrow API behavior named above; the broader roadmap, phase, runtime, and claims wording remains unpromoted. |
| `docs/design/background-service-framework-design.md` | Historical input | Focused imported design entry point. It now carries an authority note; its scheduler API examples may inform source navigation, but its canonical-design, Maturity, phase-completion, FUSE integration, performance, crash-recovery, observability, and incumbent-comparison wording is not current product proof. |
| `docs/design/background-service-framework-multithread-design.md` | Historical input | Imported multi-threaded design. `multi_threaded.rs` exposes feature-gated scheduler types, but this slice did not validate production multi-core runtime behavior, work stealing, cross-partition delivery, or operator-visible concurrency claims. |
| `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md` | Historical input | Imported phase-tracking specification for phases 5-10. It remains useful follow-up planning input, but FUSE integration, derived catalog, data cleaner, segment cleaner, compaction, and runtime validation claims require separate source/validation slices. |

### Derived-Views Architectural Pillar (TFR-019 / #1240)

Classified for TFR-019 / GitHub issue #1240 on 2026-06-24 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, the imported derived-views pillar document,
`docs/INDEX.md`, `docs/GITHUB_PR_DEVELOPMENT.md`, and bounded source/doc
searches for ValidityToken, derived-view, ViewClass, ViewBuildCost, WorkBudget,
cache-lattice, cursor-framework, resource-governor, and Forgejo-era
lane/priority/milestone wording in the current source tree. This slice does not
implement derived views, does not recreate deleted cache-lattice or
cursor-framework design docs, and does not convert historical architectural
design into current product claims.

| Path | State | Classification note |
|---|---|---|
| `docs/design/derived-views-first-class-architectural-pillar.md` | Historical input | Imported Forgejo-era derived-views architectural design with old issue #1240 metadata, P2 priority, DESIGN-M4 milestone, lane/blocking claims, `STATUS.md`/`FEATURE_MATRIX.md` references, DEPENDS-ON links to retired Forgejo issues #1173/#1176/#1237/#1239, and cache-lattice/cursor-framework/resource-governor design-spec wording. Live source has a simpler `ValidityToken` (32-byte BLAKE3 opaque token with `matches()`) in `tidefs-types-cache-lattice-core` and stub `ViewClass`/`ViewBuildCost` enums without derived-view implementations, but no multi-kind token dispatch, no six-view-type runtime, no incremental delta refresh, and no budget-governor wiring. The cache-lattice, cursor-framework, resource-governor, and WorkBudget architectural claims in the document exceed current live-source and claim-registry evidence. The file is preserved as lineage material for future review and must not be cited as current TideFS implementation status, release-readiness evidence, or product authority. |

### Unified On-Media Format Lifecycle (TFR-019 / #1242)

Classified for TFR-019 / GitHub issue #1242 on 2026-06-24 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, the imported unified-on-media-format-lifecycle
document, `docs/INDEX.md`, `docs/GITHUB_PR_DEVELOPMENT.md`,
`docs/design/on-media-format-strategy.md`, and bounded source/doc searches for
Forgejo-era issue references, design-spec, status, lane, maturity, and priority
metadata in the current documentation surface. This slice does not edit
`docs/design/on-media-format-strategy.md`, other sibling #952 leftover files,
product source, or unrelated docs.

| Path | State | Classification note |
|---|---|---|
| `docs/design/unified-on-media-format-lifecycle.md` | Historical input | Imported Forgejo-era unified five-phase lifecycle design with old issue #1238 metadata (Forgejo on `172.16.106.12`), design-spec status, P1 priority, docs lane, and cross-references to old Forgejo-era issue numbers (#1220, #1223, #1225, #1222, #1224, #1185, #1235, #1236) whose current TideFS GitHub issue mapping is undefined under TFR-019. The file defines a meta-framework for on-media record format phases (record families, feature flags, TLV extensions, rebake, golden vectors, trace oracle, torn-commit recovery) that has no current live-source implementation evidence, no claim-registry coverage, and no current format-lifecycle policy authority in the active GitHub issue and PR coordination surface. The individual format docs referenced remain canonical for their own domains under separate register rows; this lifecycle file is preserved as design lineage material and must not be cited as current TideFS implementation status, release-readiness evidence, or format-lifecycle authority. |

### IncrementalJob Core Wire-Up Deferred Design (TFR-019 / #1244)

Classified for TFR-019 / GitHub issue #1244 on 2026-06-24 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, the imported incremental-job wire-up deferred
design document, `docs/INDEX.md`, `docs/GITHUB_PR_DEVELOPMENT.md`,
`docs/design/incremental-job-core-types-crate-design.md`,
`docs/design/incremental-job-core-types-crate-design-sealed.md`, and bounded
source/doc searches for IncrementalJob, tidefs-types-incremental-job-core,
tidefs-incremental-job-core, Forgejo-era issue references, STATUS.md,
FEATURE_MATRIX.md, lane, priority, design-sealed, deferred-wire-up, and
subsystem-wire-up wording in the current source tree. This slice does not edit
product source, Cargo manifests, the sealed types/trait design docs, other
#952 leftover files, or unrelated documentation-authority files.

| Path | State | Classification note |
|---|---|---|
| `docs/design/incremental-job-core-wire-up-deferred-design.md` | Historical input | Imported Forgejo-era wire-up deferred design (old issue #2047, coordination seal #1930) with design-sealed status, design-spec maturity, storage-core lane, Forgejo-era URLs (`172.16.106.12/forgejo/forgeadmin`), and deferred wire-up claims for 14 background maintenance subsystems. The pre-existing "imported/historical design input" header annotation is consistent with this register's Historical input state: the annotation explicitly denies current policy, current spec, implementation-status evidence, release-readiness evidence, and worker scheduling authority. Live source has `tidefs-types-incremental-job-core` and `tidefs-incremental-job-core` crates implementing the sealed `IncrementalJob` trait contract, but the 14-subsystem wire-up deferral architecture, per-subsystem cursor schemas, schedule-priority table, observability contract, and subsystem-migration phases described in the document have no current live-source implementation evidence, no claim-registry coverage, and no current background-scheduler runtime authority in the active GitHub issue and PR coordination surface. The sibling sealed-types docs (`docs/design/incremental-job-core-types-crate-design.md`, `docs/design/incremental-job-core-types-crate-design-sealed.md`) remain under their own register rows. This file is preserved as lineage material for future incremental-job wire-up review and must not be cited as current TideFS implementation status, release-readiness evidence, or worker scheduling authority. |

### Release Readiness Verdict Contract (#1279)

Classified for GitHub issue #1279 on 2026-06-24 after reviewing this register's
authority rule and review method, `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`, `docs/CLAIMS_GATE_POLICY.md`,
`docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`, `docs/GITHUB_CI.md`,
`docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, the current open PR and issue
validation conventions, and bounded source inspection of
`crates/tidefs-validation/src/performance_gate/runner.rs`. This slice classifies
the verdict contract only; classification rows for the five evidence-input
documents are deferred to a follow-up issue mapped in the contract's follow-up
issue map. This slice does not edit the evidence-input documents beyond the
cross-reference additions recorded in #1279.

| Path | State | Classification note |
|---|---|---|
| `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` | Current policy | Design decision #1279 defining the release-readiness verdict boundary. Names the verdict owner, required evidence families, explicit non-claims, and the distinction between gate-local readiness receipts (such as P10-03 `GateReceipt.release_ready`, claims-gate claim status, and release-candidate evidence index) and whole-product admission. States that no release-readiness verdict exists as of 2026-06-24, that TideFS is not release-ready, and that no automated gate, CI workflow, or generated artifact may render an unqualified release-readiness claim without the verdict owner's recorded decision. Maps follow-up issues #1283 and #1284 for the remaining scoped P10-03 receipt rename/rendering work and release-facing documentation register classifications. The contract is a design/decision artifact; it does not implement a product surface, widen publishing claims, or change `validation/claims.toml`. |

### Release-Facing Evidence Inputs (#1284)

Classified for GitHub issue #1284 on 2026-06-24 after reviewing this register's
authority rule and review method, `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`
(#1279), the four release-facing evidence-input documents named by the verdict
contract, `docs/CLAIMS_GATE_POLICY.md` (already classified as Current policy),
and bounded source/doc inspection of `.github/workflows/release-candidate.yml`,
`crates/tidefs-validation/src/performance_gate/runner.rs`, and the current
open PR and issue validation conventions. This slice adds classification rows
for the four release-facing evidence-input documents that the release-readiness
verdict contract (#1279) identifies as required evidence families; the P10-03
`GateReceipt.release_ready` field rename and rendering work is left to #1283.
This slice does not edit runtime source, GitHub workflows,
`validation/claims.toml`, generated claim registry files, or unrelated
documents.

| Path | State | Classification note |
|---|---|---|
| `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` | Current spec | Documents how the Release Candidate workflow (`release-candidate.yml`) produces and indexes evidence across `smoke` and `full` profiles. Records lane job attributes (rust-smoke, nix, qemu, xfstests, rdma), artifact upload details, evidence index shape, profile selection logic, concurrency rules, and retention policies. Explicitly states the release-candidate evidence index is a **gate input, not a gate verdict**. Live-source inspection of `.github/workflows/release-candidate.yml` and the referenced lane workflows confirms the documented attributes match current workflow YAML. The contract does not make a product-readiness claim; it describes how evidence is collected so gate auditors can interpret index artifacts without tracing through YAML. The four lane-local manifest owner issues (643-646) are recorded without checking current issue state; gate auditors should verify at decision time. |
| `docs/UNRELEASED_AUTHORITY_POLICY.md` | Current policy | Binding guardrail that forbids adding or preserving legacy, backward-compatibility, migration, downgrade, or fallback behavior for unreleased TideFS data by default. Requires released external boundaries (Linux, POSIX, kernel, third-party), shipped wire/format/operator surfaces, or a temporary bridge explicitly tracked by a GitHub issue before compatibility work is permitted. Names pre-release code paths explicitly (current authority, retired pre-release path, historical input, receiptless path) instead of using "legacy." Includes a review checklist for compatibility additions. Classified as current policy consistent with its own "current policy guardrail" maturity label and live enforcement through PR review conventions. |
| `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md` | Current spec | Source-of-truth for the production-depth performance-budget, SLO, and regression-gate law. Defines the typed gate language (`family.performance_budget.performance_budget_0`) replacing benchmark folklore with first-class workload envelopes, environment profiles, KPI families, numeric budget thresholds, regression locks, and gate receipts. Section 12 documents live-source implementation evidence in `crates/tidefs-validation/src/performance_gate/`. The `GateReceipt.release_ready` field (section 12.12.5) is a **performance-gate-local** receipt requiring subject completeness, zero artifact gap, and zero budget gap; it is not a whole-product release-readiness verdict. Many categories (workload-envelope classes, environment profiles, noise policies, baseline policy families) remain at 0 implemented; the document records these gaps explicitly. The verdict contract (#1279) identifies P10-03 as a required evidence-family input and maps #1283 for the `release_ready` field rename and scope-qualified rendering. |
| `docs/GITHUB_CI.md` | Current policy | Documents the live GitHub Actions CI surface: secret boundary (GitHub is not a TideFS secret store), self-hosted runner contract, workflow shape (`Rust Fast`, `Clippy`, `Focused Rust`, `Focused Claim Validation`, `Secret Policy`, `QEMU Smoke`, `xfstests`, `RDMA`, `Release Candidate`), path-filtered PR validation, draft-PR CI skip rules, and `TIDEFS_SELF_HOSTED_READY` gating. Live-source inspection of the named workflow YAML files confirms the documented attributes match current behavior. The Release Candidate workflow is a manual-only self-hosted composition that uploads a `release-candidate-evidence-index` artifact without making a product-readiness claim. This document is a binding CI reference that complements the workflow YAML; it is not a product admission or release-readiness verdict. |

### Pool Import/Export Device Topology Design (TFR-019 / #1137)

Classified for TFR-019 / GitHub issue #1137 on 2026-06-26 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, the imported 1813 pool import/export design
document, the already-classified
`docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` register row, live source in
`crates/tidefs-types-pool-label-core/`,
`crates/tidefs-local-object-store/src/pool_importer.rs`,
`crates/tidefs-local-object-store/src/pool_exporter.rs`,
`crates/tidefs-local-object-store/src/device_manager.rs`, and
`crates/tidefs-local-object-store/src/device_health.rs`,
`validation/claims.toml` (no pool import/export claims), closed #931/#934
incumbent-comparison audit evidence, and the #952 leftover list in this
register. This slice does not edit product source, Cargo manifests,
CI workflows, validation artifacts, or `validation/claims.toml`.

| Path | State | Classification note |
|---|---|---|
| `docs/design/1813-pool-import-export-device-topology-management-design.md` | Historical input | Imported Forgejo-era #1813 design iteration for pool import/export and online device topology management. It preserves the PoolLabelV1 data structure design, import/export protocol algorithms, device failure state machine, and 7-phase implementation plan as historical design lineage. Its "design-sealed" and "frozen" language, Forgejo issue references, and phase-status claims (Phases 2–5 and 7 marked "deferred to wire-up") are stale: live source in `tidefs-local-object-store/src/pool_importer.rs`, `pool_exporter.rs`, and `device_manager.rs` implements pool import/export and device topology management referencing `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` as its design authority. The PoolLabelV1 on-device label format is implemented in `tidefs-types-pool-label-core/lib.rs`. The ZFS/Ceph prior-art comparison table in §10 is incumbent-comparison context preserved as historical design input under the #931/#934 cluster boundary; it is not a current capability, availability, durability, or product claim. No `validation/claims.toml` entries exist for pool import/export, device topology, hot-spare, evacuation, or cluster-aware pool ownership. The file is not current policy, current spec, implementation status, or product authority. |

### Retired Cluster Services Closeout Deletions (TFR-019 / #1586)

Issue #1586 deleted the already-classified Forgejo-era cluster-services seal and
completion closeout notes covered by #1153 and #1293. The source and claim
boundary findings remain unchanged: TFR-017 still blocks broad multi-node or
production cluster claims, and the deleted closeout notes are not current
policy, current spec, implementation status, release-readiness evidence, or
product authority.

### Pool Import/Export 7-Phase Implementation Plan (TFR-019 / #1152)

Classified for TFR-019 / GitHub issue #1152 on 2026-06-26 after reviewing this
register's authority rule and review method, the TFR-019 notes in
`docs/REVIEW_TODO_REGISTER.md`, the imported Forgejo #1971 phase-plan document,
closed #931/#934 incumbent-comparison evidence, the sibling #1137 classification
for the imported 1813 pool import/export design, bounded source/doc searches,
live source in `crates/tidefs-types-pool-label-core/`,
`crates/tidefs-local-object-store/src/pool_importer.rs`,
`crates/tidefs-local-object-store/src/pool_exporter.rs`,
`crates/tidefs-local-object-store/src/device_manager.rs`, and
`crates/tidefs-local-object-store/src/device_health.rs`, plus
`validation/claims.toml` and `docs/CLAIM_REGISTRY.md` (no pool import/export,
device topology, hot-spare, evacuation, or cluster-aware pool ownership claim
entries). This slice does not edit product source, Cargo manifests, CI
workflows, validation artifacts, generated claim registries, or
`validation/claims.toml`.

| Path | State | Classification note |
|---|---|---|
| `docs/design/1971-pool-import-export-7-phase-implementation-plan.md` | Historical input | Imported Forgejo-era #1971 companion implementation plan for the pool import/export and device-topology design lineage. It preserves per-phase data-structure sketches, pseudocode, tradeoff notes, and dependency mapping as historical design input. Its `design-spec` status, sealed-canonical-design wording, "DONE" and "NOT YET IMPLEMENTED" phase labels, "new" source-file notes, Forgejo issue links, and phase-completion criteria are not current implementation status, product readiness, or current authority. Live source now contains pool import/export and device-manager code paths in `tidefs-local-object-store/src/pool_importer.rs`, `pool_exporter.rs`, `device_manager.rs`, and `device_health.rs`, and PoolLabelV1 lives in `tidefs-types-pool-label-core/`; current behavior must be checked against source and current claim evidence rather than this phase plan. The ZFS prior-art, hot-spare, evacuation, online topology, cluster-lease, and public-capability wording is retained only as non-claim historical input under the #931/#934 comparator boundary. No `validation/claims.toml` or generated claim-registry entries exist for broad pool import/export, hot-spare, evacuation, device topology, or cluster-aware ownership claims. The file is not current policy, current spec, implementation status, release-readiness evidence, or product authority. |
