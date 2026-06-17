# Documentation Authority Register

Date: 2026-06-17

This register is the TFR-019 queue for imported documents that still need
authority classification. It is deliberately narrow: it does not make the
listed documents current policy, and it does not close any storage behavior
claim.

## Authority Rule

The active entry points are `README.md`, `AGENTS.md`, `docs/LICENSING.md`,
`docs/REVIEW_TODO_REGISTER.md`, `docs/WHOLE_REPO_REVIEW.md`, and this file.

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
- Delete candidate: stale duplicate, obsolete closeout note, or scaffold text
  whose useful content has already moved elsewhere.

## Review Method

Classify documents in focused commits. Do not mix doc classification with
runtime implementation except for narrow claim-gate coverage updates required
by the classification itself.

Before promoting a document to current policy or current spec, check the live
source behavior, `validation/claims.toml`, and the claims gate. If that review is
too large for the current slice, leave the document as historical input and
record the blocker in `docs/REVIEW_TODO_REGISTER.md` or
`docs/WHOLE_REPO_REVIEW.md`.

## Classified Authority Slices

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
| `docs/MEMBERSHIP_SERVICE_DESIGN.md` | Historical input | Imported design-spec for cluster membership service. References Forgejo issue #1209. Claims registry has no validated cluster-membership claim. |
| `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md` | Historical input | Imported design-spec for distributed extent redundancy with ShardGroupV1 encoding. References Forgejo issue #1286. |
| `docs/SCRUB_REPAIR_RESILVER_DESIGN.md` | Historical input | Imported design-spec for background integrity services. References Forgejo issue #1288. Claims registry has only planned/blocked scrub claims. |
| `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` | Historical input | Imported design-spec superseded by the G4 pillar at `docs/design/production-erasure-coding-crush-placement-g4-pillar.md`. References Forgejo issue #1249. |
| `docs/design/openzfs-ceph-successor-claim.md` | Historical input | Imported sealed design-spec for the OpenZFS/Ceph successor claim with 8-dimension quantitative comparison. Claims gate currently blocks publishing an OpenZFS/Ceph successor claim. |
| `docs/design/production-erasure-coding-crush-placement-g4-pillar.md` | Historical input | Imported G4 pillar design-spec for TideCRUSH deterministic placement. References Forgejo issue #1779. Supersedes earlier erasure-coding placement designs. |
| `docs/design/compression-design-strategy.md` | Historical input | Imported design-spec for compression format extension model. References Forgejo issue #1245. Transform authority blocks mounted compression claims. |
| `docs/design/2159-milestone-targets-velocity-update.md` | Historical input | Imported milestone-target architecture with May 2026 velocity assessment. Supersedes prior milestone targets. Useful coordination reference. |

## Initial Open Queue

The first mechanical pass found 87 imported documents with maturity labels or
issue-closeout wording outside the review register and whole-repo review. These
paths are not automatically wrong, but each must be classified before it can be
used as TideFS authority:

- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/GENERATION_STALENESS_DISCIPLINE_DESIGN.md`
- `docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md`
- `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`
- `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md`
- `docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md`
- `docs/POSIX_ACL_XATTR_CODEC_DESIGN.md`
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`
- `docs/SEMANTIC_OP_CANONICAL_NAME_REGISTRY_DESIGN.md`
- `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`
- `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`
- `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`
- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md`
- `docs/design/1781-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/1782-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/1806-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/2068-shard-groups-replicas-rebake-pathway-design.md`
- `docs/design/METADATA_ENGINE_PARALLELISM_DESIGN.md`
- `docs/design/background-service-framework-canonical-consolidation.md`
- `docs/design/background-service-framework-coordination-confirmed.md`
- `docs/design/background-service-framework-design-1803.md`
- `docs/design/background-service-framework-design-enhanced.md`
- `docs/design/background-service-framework-design-spec.md`
- `docs/design/background-service-framework-design.md`
- `docs/design/background-service-framework-multithread-design.md`
- `docs/design/background-service-framework-phases-5-10-wire-up-tracking-coordination-seal.md`
- `docs/design/background-service-framework-phases-5-10-wire-up-tracking.md`
- `docs/design/bounded-cluster-membership-state.md`
- `docs/design/coordination-review-roadmap-priorities-update-1953.md`
- `docs/design/deterministic-trace-oracle-system.md`
- `docs/design/device-layout-policies-adaptive-segment-sizing.md`
- `docs/design/directory-change-streams-namespace-event-protocol.md`
- `docs/design/incremental-job-core-trait-checkpoint-codec-design.md`
- `docs/design/polymorphic-extent-maps-design.md`
- `docs/design/prefetch-readahead-budgeted-speculative-io.md`
- `docs/design/rebake-architecture-ingest-journal-to-base-shard-conversion.md`
- `docs/design/refcount-delta-based-incremental-data-cleanup-queues.md`
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design-1952.md`
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design-1965.md`
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-design.md`
- `docs/design/scrub-deep-scrub-repair-resilver-orchestration-placement-ae-auditor.md`
- `docs/design/shard-groups-replicas-rebake-design-1963.md`
- `docs/design/shard-groups-replicas-rebake-design-spec.md`
- `docs/design/v1-extent-map-tristate-model.md`
- `docs/design/v1-locator-table-inline-hash.md`
- `docs/design/workload-adaptive-recordsize-and-extent-shaping.md`
