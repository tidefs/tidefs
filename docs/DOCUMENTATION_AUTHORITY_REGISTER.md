# Documentation Authority Register

Date: 2026-06-18

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
| `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` | Current spec | Design authority for the native storage-intent policy surface introduced by GitHub issue #839: guarantee/ack classes, proximity domains, workload prediction, media roles, flash-wear cost, RAM authority classes, relocation/defrag policy, operator receipt explanation, and the need for the #863 storage-intent fault-validation matrix. It is not runtime implementation evidence, a POSIX sync validation claim, a distributed availability claim, a completed fault-validation claim, or a performance superiority claim. |
| `docs/CLOCKS_TIMING_FENCES_DRIFT_ASSUMPTIONS_P8-04.md` | Historical input | Imported production-depth timing and drift law. It needs source and runtime-evidence reconciliation before it can govern distributed timing behavior. |
| `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md` | Historical input | Imported production-depth membership, placement, and failure-domain model. It remains design input until distributed membership and placement claims have runtime evidence. |
| `docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md` | Current spec | Scoped current spec for deterministic joint quorum-set identity in `crates/tidefs-membership-epoch`. It does not validate a full cluster-membership service. |
| `docs/ERASURE_CODED_LAYOUT_OW306.md` | Current spec | Scoped current spec for the deterministic single-parity erasure layout model in `crates/tidefs-replication-model`. It is not production erasure-coding placement or rebuild evidence. |
| `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` | Current spec | Scoped current spec for pool-wide placement contract and property-tested local model behavior. It does not prove distributed availability, rebake, recovery, or operator lifecycle behavior. |
| `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` | Current spec | Scoped current spec for the issue #18 placement receipt authority split, including the shared `PlacementReceiptRef` policy-satisfying gate and remaining follow-up issues #674, #675, and #676. It is not a closure claim for distributed availability, rebuild, rebake, reclaim, or runtime validation. |
| `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md` | Historical input | Imported production-depth replication, rebuild, and relocation flow design. It is not current runtime proof for anti-entropy, repair rebuild, relocation, failover, or cutover drains. |

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
