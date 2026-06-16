# Documentation Authority Register

Date: 2026-06-01

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

## Initial Open Queue

The first mechanical pass found 87 imported documents with maturity labels or
issue-closeout wording outside the review register and whole-repo review. These
paths are not automatically wrong, but each must be classified before it can be
used as TideFS authority:

- `docs/BLAKE3_USAGE_POLICY.md`
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`
- `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`
- `docs/CLAIMS_GATE_POLICY.md`
- `docs/CLUSTER_TRANSPORT_BOUNDEDNESS_DESIGN.md`
- `docs/DATASET_FEATURE_FLAGS_DESIGN.md`
- `docs/DATASET_LIFECYCLE_DESIGN.md`
- `docs/DEBUGGING_WORKFLOWS.md`
- `docs/DEFERRED_CLEANUP_WORK_QUEUES_DESIGN.md`
- `docs/DESIGN_OVERFITTING_POLICY.md`
- `docs/DETERMINISTIC_TRACE_ORACLE_DESIGN.md`
- `docs/DEVICE_LAYOUT_POLICIES_DESIGN.md`
- `docs/DISTRIBUTED_OPERATOR_PRODUCT_SURFACE_BLOCKER_MAP_OW307D.md`
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md`
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`
- `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`
- `docs/FUSE_OPERATION_COVERAGE_MATRIX.md`
- `docs/GENERATION_STALENESS_DISCIPLINE_DESIGN.md`
- `docs/HUMAN_TERMINOLOGY.md`
- `docs/INTENT_LOG_SYNC_WRITE_LATENCY_PC008.md`
- `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`
- `docs/MEMBERSHIP_SERVICE_DESIGN.md`
- `docs/MODULE_OWNERS_INVARIANTS_PC002.md`
- `docs/ON_DISK_FORMAT_VERSIONING_AND_COMPATIBILITY_POLICY.md`
- `docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md`
- `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`
- `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md`
- `docs/POLYMORPHIC_XATTR_STORAGE_DESIGN.md`
- `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`
- `docs/POSIX_ACL_XATTR_CODEC_DESIGN.md`
- `docs/PREVIEW_USER_MANUAL.md`
- `docs/RDMA_TRANSPORT_POSITION.md`
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`
- `docs/SCRUB_REPAIR_RESILVER_DESIGN.md`
- `docs/SEMANTIC_OP_CANONICAL_NAME_REGISTRY_DESIGN.md`
- `docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`
- `docs/SNAPSHOT_DEADLIST_PINNING_DESIGN.md`
- `docs/SPACEMAP_ALLOCATOR_DESIGN.md`
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`
- `docs/TRANSACTION_COMMIT_GROUPS_PC007.md`
- `docs/TXG_STATE_MACHINE_DESIGN.md`
- `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`
- `docs/UNIVERSAL_INCREMENTAL_CURSOR_FRAMEWORK_DESIGN.md`
- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md`
- `docs/VFS_ENGINE_API_CONTRACT.md`
- `docs/design/1683-checksum-architecture-g3-pillar-design-spec.md`
- `docs/design/1781-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/1782-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/1806-shard-groups-replicas-rebake-design-spec.md`
- `docs/design/2068-shard-groups-replicas-rebake-pathway-design.md`
- `docs/design/2159-milestone-targets-velocity-update.md`
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
- `docs/design/compression-design-strategy.md`
- `docs/design/coordination-review-roadmap-priorities-update-1953.md`
- `docs/design/deterministic-trace-oracle-system.md`
- `docs/design/device-layout-policies-adaptive-segment-sizing.md`
- `docs/design/directory-change-streams-namespace-event-protocol.md`
- `docs/design/end-to-end-checksum-architecture-g3-pillar.md`
- `docs/design/incremental-job-core-trait-checkpoint-codec-design.md`
- `docs/design/openzfs-ceph-successor-claim.md`
- `docs/design/polymorphic-extent-maps-design.md`
- `docs/design/prefetch-readahead-budgeted-speculative-io.md`
- `docs/design/production-erasure-coding-crush-placement-g4-pillar.md`
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
- `docs/security/blake3-integrity-boundary.md`
- `docs/troubleshooting-build.md`
