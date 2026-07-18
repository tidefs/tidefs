# Documentation Authority Register

Date: 2026-06-30

This register is the TFR-019 queue for documents that still need authority
classification. It is deliberately narrow: it does not make the listed
documents current policy, and it does not close any storage behavior claim.

## Authority Rule

The active entry points are `README.md`, `AGENTS.md`, `docs/INDEX.md`,
`docs/LICENSING.md`, `docs/REVIEW_TODO_POLICY.md`,
`docs/REVIEW_TODO_REGISTER.md`, `docs/CLAIMS_GATE_POLICY.md`, and this file.

Issue #1871 deleted the TideFS Book source because its useful current
boundaries are already represented by the active entry points, source-owned
`tidefsctl` command classification, operator UAPI authority, and claims gate.
Do not recreate a replacement book, manual, or status surface without an
issue-scoped authority decision.

All other imported documents are review inputs until classified here or in a
small follow-up commit tied to TFR-019. Documents under `docs/design/`, root
documents ending in `_DESIGN.md`, issue-era implementation plans, old status
matrices, coordination packets, closeout snapshots, and Forgejo-era milestone
updates are historical input by default even when their text says
`Maturity:`, `Status: sealed`, `canonical`, `single authoritative`, phase
complete, implemented, or current. That wording is imported context, not
current authority.

A document becomes current policy or current spec only through source-backed
classification that names the narrow scope being promoted. Product-facing,
successor, comparator, release-readiness, durability, safety, performance,
availability, or production wording still requires the claims gate and current
validation evidence for that exact scope.

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
record the blocker in `docs/REVIEW_TODO_REGISTER.md`.

Consolidation work must collapse duplicate truth surfaces instead of creating
new status files. Keep generated outputs generated, especially
`docs/CLAIM_REGISTRY.md` from `validation/claims.toml`. Treat broad design docs,
old status matrices, coordination packets, closeout snapshots, and issue-era
implementation plans as historical input or delete candidates until a focused
issue classifies their exact scope. Delete after useful current content has
moved or the file is obsolete scaffold/closeout material; keep deleted-path
lineage in git, issues, and PRs instead of preserving a live register row for
every deleted file.

## CI And Validation Root Cleanup (TFR-019 / #1648)

Issue #1648 folded the hidden CI and validation root-document family into
`docs/GITHUB_CI.md` and deleted the unreferenced standalone roots instead of
keeping a second CI-authority surface. `docs/DEPENDENCY_ADVISORY_CI.md` remains
as the narrow remediation guide linked from the live `Dependency Advisory`
workflow summary; it is now discoverable through `docs/GITHUB_CI.md`.

Deleted paths from this cleanup keep lineage in git, issue #1648, and the pull
request only:

- `docs/ACTIONLINT_CI.md`
- `docs/CARGO_METADATA_AUDIT.md`
- `docs/CI_PATH_FILTER_CONTRACT.md`
- `docs/FOCUSED_CLAIM_INPUT_CONTRACT.md`
- `docs/FOCUSED_RUST_INPUT_CONTRACT.md`
- `docs/KERNEL_FSYNC_VALIDATION_CONTRACT.md`
- `docs/KERNEL_MMAP_VALIDATION_CONTRACT.md`
- `docs/KERNEL_MODULE_BUILD_REQUIREMENTS.md`
- `docs/NIX_CI_OUTPUT_CONTRACT.md`
- `docs/RDMA_VALIDATION_CONTRACT.md`
- `docs/SECRET_POLICY_CI_CONTRACT.md`
- `docs/SELF_HOSTED_RUNNER_CONTRACT.md`

This cleanup does not edit workflow behavior, add release or production
readiness evidence, validate successor/comparator claims, or promote CI
artifacts into product-proof authority beyond the exact validation lanes named
in `docs/GITHUB_CI.md`.

## Folded Claim And Consolidation Bridge (#1588)

Issue #1588 folded the temporary claim/consolidation bridge into existing
authority docs and deleted it as a separate policy surface. Successor and
comparator wording now lives in `docs/CLAIMS_GATE_POLICY.md`; the storage-intent
receipt and non-claim spine lives in `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`;
TFR-019 classification and deletion process stays in this register. This did
not validate `storage.local.successor_comparator.v1`,
`storage.distributed.successor_comparator.v1`, or the umbrella
`storage.intent.successor_comparator.v1`, declare release or production
readiness, classify every imported document, or close TFR-019.

Issue #1607 deleted `docs/design/openzfs-ceph-successor-claim.md` as a
duplicate historical claim packet. Its lineage remains in git, the issue, and
the PR only; current successor/comparator authority is limited to
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, and
`docs/CLAIMS_GATE_POLICY.md`, with the split and umbrella claim ids still
blocked until their exact evidence manifests validate.

## Product Admission Overlay Fold-Down (#1594)

Issue #1594 moves the product-spine admission map into
`validation/claims.toml` and the generated `docs/CLAIM_REGISTRY.md`. The
deleted `docs/PRODUCT_ADMISSION_PROOF_TRAINS.md` was a planning overlay whose
useful gate shape is now registry-backed by claim ids, evidence classes,
authority paths, admission rules, and explicit blockers. Keep the deleted-path
lineage in git, the issue, and the PR rather than preserving a live duplicate
status document.

This fold-down does not validate local or distributed successor/comparator
claims, create a release-readiness verdict, promote proof-train labels into
product proof, or close TFR-019. Product-facing wording must still route
through the generated claim registry, `docs/CLAIMS_GATE_POLICY.md`, current
evidence manifests, and `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.

## Third-Wave Historical Input Deletions (TFR-019 / #1612)

Issue #1612 deleted another small family of historical inputs whose live file
presence kept competing with current authority for FUSE/POSIX, local recovery
and object-store, and operator-product-surface wording:
`docs/FUSE_OPERATION_COVERAGE_MATRIX.md`, `docs/POSIX_SUBSET.md`,
`docs/POSIX_SEMANTICS_OW106.md`, `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md`,
`docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md`, and
`docs/OPERATOR_MANUAL_DYNAMIC_TUNING_AND_REALTIME_OBSERVABILITY.md`.

Their lineage now lives in git, issue #1612, and its pull request. Current
claims and product-shape authority remains with source-backed focused docs,
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`,
`docs/CLAIMS_GATE_POLICY.md`, `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`,
and live GitHub issues/PRs. This deletion does not validate any
successor/comparator, production, release-readiness, POSIX-completeness,
crash-recovery, or operator-product claim.

## Block P6 Historical Input Deletions (TFR-019 / #1614)

Issue #1614 deleted the stale block/ublk P6 historical inputs whose live files
still read like production source-of-truth documents:
`docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`,
`docs/EXPORT_FENCING_RESIZE_FAILOVER_RUNTIME_P6-03.md`, and
`docs/BLOCK_ACCEPTANCE_STRESS_HARNESS_MATRIX_P6-04.md`.

Their lineage now lives in git, issue #1614, and its pull request. Current
block-device authority remains with the scoped OW-301 block-volume docs,
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, and
`docs/CLAIMS_GATE_POLICY.md`. This deletion does not validate fio workload
breadth, mkfs/mount acceptance, online resize, crash durability, production
block-device readiness, kernel block readiness, or OpenZFS/Ceph-class wording.

## Publication P3 Historical Input Deletion (TFR-019 / #1617)

Issue #1617 deleted the stale publication-pipeline runtime decomposition input
whose live file still read like a production source-of-truth document:
`docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`.

Its lineage now lives in git, issue #1617, and its pull request. Current
publication, receipt, policy, and product-claim authority remains with
source-backed current specs such as `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`,
`docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`,
`docs/TRANSFORM_PIPELINE_AUTHORITY.md`, `validation/claims.toml`, generated
`docs/CLAIM_REGISTRY.md`, and `docs/CLAIMS_GATE_POLICY.md`. This deletion does
not validate a full publication pipeline, response-emission runtime,
distributed commit path, policy runtime service, production readiness, or
OpenZFS/Ceph-class wording.

## Refcount-Delta Historical Root Deletion (TFR-019 / #1677)

Issue #1677 deleted the stale refcount-delta cleanup-queue historical root.
Current reclaim/deadlist and compaction boundaries remain with source behavior,
`docs/COMPACTION_AUTHORITY.md`, `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`,
`validation/claims.toml`, and `docs/CLAIMS_GATE_POLICY.md`; this deletion does
not validate runtime reclaim, deadlist, compaction, allocator, release,
production, performance, availability, or successor/comparator claims.

## Intent-Log Latency Historical Root Deletion (TFR-019 / #1679)

Issue #1679 deleted the stale PC-008 intent-log sync-write latency historical
root. The current boundary remains with source-backed local-filesystem
constants/tests, `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`,
`validation/claims.toml`, and `docs/CLAIMS_GATE_POLICY.md`; this deletion does
not validate persistent WAL, bounded-latency SLO, fsync, O_DSYNC, mmap
durability, block/ublk, production, performance, availability, or
successor/comparator claims.

## Transaction Commit Groups Historical Root Deletion (TFR-019 / #1681)

Issue #1681 deleted the stale PC-007 transaction/commit-group historical root.
Current authority remains with source-backed local-filesystem transaction,
dirty-state, root-publication, and FUSE fsync/fdatasync code and tests; this
does not validate POSIX-complete durability, O_DSYNC/open-flag handling, block
flush/FUA, distributed transactions, performance, availability, release
readiness, or successor/comparator claims.

## Device Layout Policy Historical Root Deletion (TFR-019 / #1684)

Issue #1684 deleted the stale device-layout policy root that self-declared it
was superseded by a later adaptive-segment-sizing design input that issue #1720
also deleted. Current authority remains with source-backed device-layout code,
live issues, validation claims, and the claims gate; these deletions do not
validate adaptive layout production readiness, import-performance scalability,
allocator/device lifecycle completeness, availability, release readiness, or
successor/comparator claims.

## Production Integrity Historical Root Deletion (TFR-019 / #1832)

Issue #1832 deleted the stale `docs/PRODUCTION_INTEGRITY_POLICY.md`
historical root after its useful current content was already covered by
source-backed local-object-store constants and tests,
`docs/BLAKE3_USAGE_POLICY.md`, `docs/ROOT_AUTHENTICATION_OW015.md`,
`validation/claims.toml`, and `docs/CLAIMS_GATE_POLICY.md`. The deletion does
not validate production integrity, root-authentication key management, online
scrub or self-heal, migration, mounted FUSE/kernel behavior, release
readiness, or successor/comparator claims.

## Historical Input Fat Deletions (TFR-019 / #1720)

Issue #1720 deleted stale historical roots whose remaining useful content was
already covered by source, current authority docs, the review register, claims
gate policy, git history, or GitHub issue/PR lineage. The deleted paths are:

- `docs/TORN_COMMIT_RECOVERY_CONTRACT.md`
- `docs/adr/0002-persistent-orphan-index.md`
- `docs/crates/types-core-consolidation-plan.md`
- `docs/security/blake3-integrity-boundary.md`
- `docs/DESIGN_OVERFITTING_POLICY.md`
- `docs/DATASET_LIFECYCLE_DESIGN.md`
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md`
- `docs/UNIFIED_RESOURCE_GOVERNOR_DESIGN.md`
- `docs/VFS_ENGINE_API_CONTRACT.md`
- `docs/design/compression-design-strategy.md`
- `docs/design/device-layout-policies-adaptive-segment-sizing.md`

Current authority remains with source-owned crate comments and APIs,
`docs/BLAKE3_USAGE_POLICY.md`, `docs/REQUEST_CONTRACT.md`,
`docs/INODE_NAMESPACE_AUTHORITY.md`, `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`,
`docs/STORAGE_INTENT_POLICY_AUTHORITY.md`, `docs/TRANSFORM_PIPELINE_AUTHORITY.md`,
`docs/workspace-package-classification.md`, `validation/claims.toml`, and
`docs/CLAIMS_GATE_POLICY.md`. This deletion family does not validate VFS
runtime completeness, dataset lifecycle closure, full space-accounting or
resource-governor authority, mounted transform support, production checksum or
recovery behavior, release readiness, performance, availability, or
successor/comparator wording.

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
`docs/REVIEW_TODO_REGISTER.md`, this register, generated claim registry data,
and live GitHub/git evidence; those surfaces intentionally record retired
crates, deleted docs, and old paths as authority evidence rather than rewrite
targets.

The #952 live-doc cleanup is split into exact-file child slices. Those paths
stay out of this coordination slice:

- #1015 owns current-doc retired scaffold root references in
  `docs/ARCHITECTURE.md`.
- #1016 owned earlier status/matrix link cleanup inside the duplicate manual;
  #1775 deletes the remaining duplicate manual/matrix pair, with exact path
  lineage retained by git history and GitHub issues/PRs instead of live docs.
- #1017 owns the visible historical-input treatment for retired crate paths in
  `docs/HUMAN_TERMINOLOGY.md`.
- #1018 owned historical/evidence treatment for retired type-root
  consolidation records; #1720 deleted the remaining standalone plan root, so
  git history and GitHub lineage retain that path.
- #1019's retired type-root dependency-table cleanup is superseded for
  package-authority by #1838: current package roles use
  `docs/workspace-package-classification.md`, live cargo metadata, and
  GitHub issue/PR lineage; git history retains the stale ADR/design path
  lineage.
- #1021 owns the deleted `docs/FEATURE_MATRIX.md` reference in
  `docs/design/deterministic-cluster-simnet-protocol-correctness-testing.md`.
- #1635 deleted the former #1022/#1023 design-subdir cleanup/orphan-index
  duplicate roots as historical residue; git history and the GitHub issues/PR
  retain the path lineage.
- #1024 owns deleted status/matrix delivery outputs in
  `docs/design/node-lifecycle-management.md`.
- #1590 deleted the
  `docs/design/deferred-cleanup-background-service-scheduling.md` historical
  status/update target along with the background-service duplicate family.

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

### Duplicate Design Family Deletions (TFR-019 / #1590)

Issue #1590 deleted the obvious stale worklog/status documents and duplicate
Forgejo-era design-family files for background service scheduling,
scrub/repair/resilver, shard/rebake, pool import/export, and incremental-job
wire-up. The deleted files were historical lineage, phase-tracking, or
sealed/canonical-design variants whose useful current content either moved into
existing source-backed authority paths or remains available in git history.

The surviving source-backed surfaces are:

- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` for the current scheduler/job
  contract summary.
- `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` for the current
  pool-label, scan/import, local import/export, and device-manager summary.
- `docs/SCRUB_IDENTITY_AUTHORITY.md`,
  `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`, and
  `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md` for narrow current
  scrub/receipt/placement authority.

This register intentionally does not keep a live row for every deleted
duplicate. Git history and GitHub issue/PR history retain the path lineage.

### Second-Wave Historical Design Deletions (TFR-019 / #1595)

Issue #1595 deleted a second wave of historical design inputs whose live-looking
status, phase-complete, canonical, sealed, or implementation-plan wording could
be mistaken for current authority. The deleted set covered duplicate or stale
cluster transport, trace-oracle, extent/locator, generation-staleness,
semantic-op, cursor, metadata-parallelism, membership, directory-stream,
prefetch/readahead, locator, and record-shaping designs, plus the old
ZFS/Ceph mistake coverage matrix. Their useful current boundaries are either
already represented by surviving source-backed authority docs, issue state,
validation policy, or the split successor/comparator claim ids in
`validation/claims.toml`.

This register intentionally records the deletion as a family-level authority
cleanup instead of keeping live rows for every removed path. Git history, issue
#1595, and its pull request retain the deleted-path lineage.

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

### Stale Marker Classifications (TFR-019 / #1590)

Issue #1590 also classified surviving Markdown files that still carried
Forgejo-era URLs or live-looking imported status markers. Issue #1720 later
deleted the last standalone historical rows from this section; git history,
issue #1590, and issue #1720 retain their lineage.

### Three-Contract Historical Root Deletion (TFR-019 / #1692)

Issue #1692 deleted the stale three-contract architecture root instead of
preserving it as another live historical Markdown authority surface. Current
on-media, VFS, trace, claim, and product-shape authority remains with
source-backed focused docs, `validation/claims.toml`, the generated claim
registry, the claims gate, and live GitHub issues/PRs. This deletion does not
validate multi-implementation equivalence, trace parity, format lifecycle
completion, release readiness, comparator parity, or OpenZFS/Ceph-successor
claims.

### Historical ADR Root Deletion (TFR-019 / #1689)

Issue #1689 deleted the stale checksum and commit-ordering ADR roots instead of
keeping them as live historical Markdown. Current checksum and BLAKE3 authority
remains with source-backed policy/spec inputs, `validation/claims.toml`, the
generated claim registry, and the claims gate. Current transaction and commit
behavior remains with source, tests, live issues, validation claims, and the
claims gate. This deletion does not validate checksum architecture completion,
commit-group crash consistency, pool-layer production readiness, release
readiness, comparator parity, or OpenZFS/Ceph successor/comparator wording.

### Historical Kbuild Toolchain Note Deletion (TFR-019 / #1685)

Issue #1685 deleted the standalone historical Linux 7.0 Kbuild toolchain
preparation note. Current Kbuild toolchain behavior remains in
`nix/vm/k7-kbuild-toolchain.nix`, `flake.nix`, and
`scripts/k7-kbuild-toolchain-prepare.sh`; current workflow policy remains in
`docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`. The deleted note is git,
issue, and PR lineage only, not Kbuild, QEMU, kernel runtime, release, or
OpenZFS/Ceph-successor evidence.

### Empty Module Owners Scaffold Retirement (TFR-019 / #1619)

Issue #1619 deleted the empty `MODULE_OWNERS_INVARIANTS_PC002` scaffold and
retired its xtask aliases because the document had no owner-path rows to
verify. Module ownership, subsystem invariants, release readiness, production
readiness, and OpenZFS/Ceph-class wording remain blocked until a future
source-backed issue introduces real owner-path data, validation evidence, and
claim-gate coverage for an exact scope.

### Nextgen Verification Root Retirements (TFR-021 / #1656, #1660)

Issue #1656 deleted the old issue #281 nextgen verification roadmap as a
superseded live roadmap root. This cleanup collapses
`docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md` itself from an
integrated program roadmap into a bounded historical pointer and current
authority index. Current TFR-021 authority lives in `docs/CLAIMS_GATE_POLICY.md`,
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, evidence manifest
schemas/source, focused subsystem docs, CI docs, and live GitHub issues/PRs for
the exact slice. The deleted #281 roadmap and the retired nextgen follow-up map
remain lineage in git, issue, and PR history only; they are not current planning
authority and must not be cited as product-readiness, release, successor,
crash-safety, performance-isolation, kernel, distributed, RDMA, or offload
evidence.

Issue #1660 deleted the standalone issue #751 evidence-chain authority root for
the same reason: its useful evidence-chain decision is carried by
`validation/claims.toml`, `docs/CLAIMS_GATE_POLICY.md`, generated
`docs/CLAIM_REGISTRY.md`, and the source-backed `EvidenceArtifactManifest`
tooling. The deleted path remains lineage in git, issue, and PR history only.
It is not a separate current authority and must not be cited as claim closure,
product proof, or release-readiness evidence.

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

### Storage Design Duplicate Root Deletions (TFR-019 / #1635)

Issue #1635 deleted duplicate `docs/design/` roots for checksum architecture,
dataset lifecycle, commit-group/TXG ordering, deferred cleanup queues, and the
persistent orphan index. The surviving historical inputs are the root design
docs and historical ADRs already classified in this register. Git history and
GitHub issue/PR history retain the deleted-path lineage; this register does not
keep live per-file rows for those deleted duplicates.

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
| `docs/DATASET_FEATURE_FLAGS_DESIGN.md` | Historical input | Retained only as a provenance pointer while active issue #1842 owns the remaining `xtask/tidefs-xtask/src/cluster.rs` citations and source comments still consume the feature-flag type vocabulary. Current authority lives in `crates/tidefs-types-dataset-feature-flags-core/src/lib.rs`, source callers, `validation/claims.toml`, and the claims gate; this file is not a public compatibility promise or mounted feature-negotiation claim. |
| `docs/SPACEMAP_ALLOCATOR_DESIGN.md` | Historical input | Retained only as a provenance pointer while active issue #1842 owns the remaining `xtask/tidefs-xtask/src/storage.rs` citation. Current authority lives in `crates/tidefs-spacemap-allocator/src/lib.rs`, source callers, current capacity/storage-intent authority, `validation/claims.toml`, and the claims gate; this file is not runtime allocator proof, capacity authority, or an OpenZFS comparison surface. |
| `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md` | Historical input | Retained only as a provenance pointer while source comments still name this historical path. Current authority lives in `crates/tidefs-types-polymorphic-directory-index-core/src/lib.rs`, source callers, `validation/claims.toml`, and the claims gate; this file is not namespace authority, directory-index completeness proof, performance evidence, production-readiness evidence, or a ZFS ZAP comparison surface. |
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

Issue #1637 deleted the OW-301 block-volume receipt/spec roots and the older
projection charter as duplicate live Markdown authority surfaces. The useful
current boundary is folded into the surviving started-export admission artifact
doc below, source code, generated claim registry, validation artifacts, git
history, and PR/issue lineage. This consolidation does not validate qid/tag
completion as a product claim, unblock the block-device product boundary, or
claim fio breadth, mkfs/mount acceptance, online resize, crash durability,
kernel block readiness, release readiness, production readiness, or
OpenZFS/Ceph successor status.

| Path | State | Classification note |
|---|---|---|
| `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md` | Current spec | Scoped current spec for the started-export admission artifact and fail-closed verification path. It does not close broader block-volume runtime validation. |

**FUSE/POSIX adapter docs**

| Path | State | Classification note |
|---|---|---|
| `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md` | Current policy | Binding only as the adapter-boundary guardrail that prevents runtime FUSE handlers from bypassing the TideFS request/VfsEngine path into storage mutation authority. It does not close xfstests rows or broader POSIX/FUSE completeness. |
| `docs/FUSE_LSEEK_PC004B.md` | Current spec | Scoped current spec for the non-release dense-file preview `lseek` behavior described in the file. It does not claim sparse-file fidelity or parent POSIX-complete FUSE closure. |
| `docs/design/clustered-posix-lock-forwarding-boundary.md` | Current spec | Scoped current spec for the clustered POSIX mounted LOCK forwarding boundary decided by GitHub issue #626. It names the future mounted owner for `LockServiceHandle` construction and follow-up issue split, but it is not implementation evidence that clustered POSIX mounts exist today. |

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

Issue #1715 deleted the imported authn/authz/override/audit and
upgrade/failover/cutover operator-runbook production-depth roots instead of
preserving them as live historical surfaces. Current operator security
authority remains with source-owned `crates/tidefs-auth/`,
`docs/security/operator-authz-boundary.md`, `docs/OPERATOR_UAPI_AUTHORITY.md`,
and `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`. This deletion does not
implement production remote operator authorization, a production runbook engine,
release readiness, OpenZFS/Ceph parity, distributed failover readiness, kernel
residency, or successor/comparator wording.

Issue #1717 deletes the imported membership/placement, replication/rebuild/
relocation, and timing/drift production-depth roots instead of preserving them
as live historical surfaces. Current authority remains with source-owned
membership, receipt, replication, rebuild, relocation, and clock-timing crates,
plus `docs/MEMBERSHIP_AUTHORITY.md`,
`docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`,
`docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, `validation/claims.toml`, and the
claims gate. This deletion does not implement distributed membership runtime
closure, production replication or rebuild, clock-drift runtime validation,
release readiness, OpenZFS/Ceph parity, or successor/comparator wording.

### Membership-Service Historical Root Deletion (TFR-019 / #1835)

Issue #1835 deleted the imported membership-service root after replacing the
remaining live references with current membership authority, quorum-set
identity, storage-intent policy, source-owned membership crates, validation
claims, and live GitHub issue/PR authority. Its lineage remains in git, issue
#1835, and its pull request only. This deletion does not implement or validate
a full cluster-membership service, distributed availability, production
readiness, release readiness, OpenZFS/Ceph parity, performance,
successor/comparator wording, or operator-readiness claims.

### Polymorphic Xattr Historical Root Deletion (TFR-019 / #1836)

Issue #1836 deleted the imported polymorphic-xattr storage root after
replacing its remaining live references with source-owned type, runtime,
local-filesystem, FUSE, and kernel paths, validation claims, and live GitHub
issue/PR authority. Its lineage remains in git, issue #1836, and its pull
request only. Issue #1448 separately owns the userspace xattr/statx probe
safety gap. This deletion does not implement or validate external xattr B-tree
persistence, mounted xattr or POSIX ACL behavior, kernel/userspace equivalence,
POSIX completeness, production or release readiness, performance, or
successor/comparator wording.

## Incumbent Comparison Audit Slice (#931)

This initial #931 slice classifies the following legacy incumbent-comparison
sections as historical design lessons or fail-closed review blockers, not
current TideFS product evidence. None of these documents may be cited for a
current OpenZFS, ZFS, Ceph, DRBD, ext4/XFS, performance-superiority,
cost-effectiveness, flash-wear, RAM, WAN, durability, or successor claim
unless the cited statement is re-expressed through
`storage.local.successor_comparator.v1` or
`storage.distributed.successor_comparator.v1` and the comparator evidence
required by those registry entries:

- Deleted orphan-index comparison lineage: ZFS/ext4/CephFS orphan-index table
  and former "key advantages" list are non-claim design lessons in git history
  only.
- `docs/POLYMORPHIC_DIRECTORY_INDEX_DESIGN.md`: ZFS ZAP comparison and former
  "improvements over ZFS" list are non-claim design lessons.
- Deleted polymorphic extent-map design lineage: ZFS/Ceph extent-layout tables,
  random-read cost hypotheses, and design-mistake coverage remain non-claim
  historical lessons in git history only.
- Deleted membership-service comparison lineage: ZFS/Ceph cluster-membership
  comparison text remains non-claim historical input in git history only.
- The deleted shard/rebake design-family comparison text about ZFS/Ceph
  deferred redundancy and write amplification is design input only.
- `docs/ONLINE_DEFRAG_BPR_DESIGN.md`: ZFS/Ceph defrag and BPR comparison text
  is target mechanism input, not evidence of implemented online defrag; its
  BPR mechanism is subordinate to #848 storage-intent relocation gates, #844/#856
  cost and wear evidence, #845 prediction/payback evidence, and #904 media
  capability evidence.
- Retired review surfaces: incumbent references are fail-closed review blockers
  only.

### ADR-Backed Historical Root Deletions (TFR-019 / #1675)

Issue #1675 deleted the ADR-backed commit-group and orphan-index historical
root docs whose useful target-history context was already preserved by ADRs and
source code. The surviving ADRs remain historical input only; live behavior,
current authority, and product claims still come from source-backed authority
docs, `validation/claims.toml`, generated claim output, and GitHub issue/PR
state.

Non-overlapping child slices completed the cluster-by-cluster audit and added
Incumbent Comparison Boundary sections to the following file groups. Each
grouped file is classified as historical/design input only for its comparison
text; no product-facing successor, superiority, or parity wording exists in
any of these files without the matching split successor/comparator claim id and
its comparator evidence.

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

Consolidation closure (issue #1802):
- `docs/ARCHITECTURE.md`: ZFS/CephFS comparison body text was deleted from the
  live architecture map. Incumbent comparison lineage remains available through
  git, issues, PRs, claim registry data, and validation evidence instead of a
  live review section in this document.

This consolidation closes the #931 audit. No live doc contains un-gated
incumbent-comparison, successor, or product-superiority wording. Any future
product-facing comparison must route through the matching split
successor/comparator claim id and comparator evidence.

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
| `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` | Current spec | Scoped source-backed summary for the current background scheduler and incremental-job contract in `crates/tidefs-background-scheduler`, `crates/tidefs-incremental-job-core`, and `crates/tidefs-types-incremental-job-core`. It is not release-readiness evidence or proof that every maintenance subsystem is wired into mounted runtime behavior. |

### Unreferenced Historical Input Deletions (TFR-019 / #1673)

Issue #1673 deleted `docs/troubleshooting-build.md` and
`docs/design/derived-views-first-class-architectural-pillar.md` after bounded
search found no live source, validation, or current-authority references
outside this register. Their lineage remains in git, issue #1673, and the pull
request. This deletion does not create build/troubleshooting authority,
derived-view implementation evidence, release-readiness evidence, or product
claims.

### Format Lifecycle Historical Root Deletions (TFR-019 / #1705)

Issue #1705 deleted the imported unified format-lifecycle and deterministic
crash-injection design roots instead of preserving them as live historical
surfaces. Their design-spec/status wording came from old Forgejo-era planning,
depended on absent or undefined imported issue paths, and did not match a
current source-backed product authority surface. Their lineage remains in git,
issue #1705, and its pull request only.

Current format and crash evidence remains with the relevant source crates,
validation artifacts, claim registry, release-readiness contract, trace/crash
oracle authority surfaces, and live GitHub issues/PRs. This deletion does not
promote production format lifecycle, complete crash-injection coverage, runtime
crash-safety claims, release readiness, OpenZFS/Ceph parity, or
successor/comparator wording.

### Kernel Boundary Production Root Deletions (TFR-019 / #1707)

Issue #1707 deleted the imported Linux-baseline, std/no_std environment,
UAPI/FFI schema, Rust-for-Linux trait, kernel rollout, and kernel
locking/RCU/workqueue production-depth roots instead of preserving them as
live historical surfaces. Those roots were already classified as historical
input, depended on deleted blueprint-era law documents, and competed with the
current source-backed kernel and preview-UAPI authority surfaces.

Current kernel and preview-UAPI authority remains with the scoped kernel
residency decision, kernel-resident pool-engine architecture, Linux workflow
policy, preview UAPI boundary, operator UAPI authority, kmod READMEs/source,
validation claims, claims-gate policy, and live GitHub issues/PRs. This
deletion does not promote production kernel residency, full-kernel/no-daemon
readiness, production UAPI/ABI freeze, kernel block or POSIX parity, release
readiness, OpenZFS/Ceph parity, or successor/comparator wording.

### P3 Policy And Receipt Root Deletions (TFR-019 / #1709)

Issue #1709 deleted the imported policy-authority runtime-surface and
receipt/response runtime-emission production-depth roots instead of preserving
them as live historical surfaces. Those roots were already classified as
historical input, used source-of-truth wording wider than current source-backed
implementation, and competed with the scoped storage-intent, receipt,
result/refusal, operator, and claims-gate authority surfaces.

Current authority remains with `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`,
`docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`,
`docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md`,
`docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`,
`docs/OPERATOR_UAPI_AUTHORITY.md`, `docs/CLAIMS_GATE_POLICY.md`,
`validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, source behavior,
and live GitHub issues/PRs. This deletion does not promote a complete
kernel-hosted policy authority service, runtime-fed operator product surface,
response-registry runtime, receipt runtime closure, release readiness,
OpenZFS/Ceph parity, or successor/comparator wording.

### Performance And Fault Root Deletions (TFR-019 / #1712)

Issue #1712 deleted the imported performance-budget/SLO/regression-gate
and fault-injection/chaos/corruption production-depth roots instead of
preserving them as live historical surfaces. The performance root was already
classified as historical input, and the fault root still called itself
source-of-truth even though current proof lives in source, validation
artifacts, release evidence, and claims policy.

Current performance-gate authority remains with
`crates/tidefs-validation/src/performance_gate/`, `xtask` command behavior,
`docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md`,
`docs/RELEASE_READINESS_VERDICT_CONTRACT.md`, `docs/GITHUB_CI.md`,
`docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, generated
`docs/CLAIM_REGISTRY.md`, and live validation artifacts. Current typed
fault-catalog and fault-scenario authority remains with
`crates/tidefs-local-object-store/src/fault_catalog.rs`,
`crates/tidefs-local-object-store/src/fault_injection.rs`,
`crates/tidefs-validation/src/fault_injection_scenario_catalog.rs`, release
evidence, claims policy, and live GitHub issues/PRs. This deletion does not
validate release readiness, production fault campaigns, performance budget
completeness, full POSIX/block/kernel readiness, OpenZFS/Ceph parity, or
successor/comparator wording.

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

### Retired Cluster Services Closeout Deletions (TFR-019 / #1586)

Issue #1586 deleted the already-classified Forgejo-era cluster-services seal and
completion closeout notes covered by #1153 and #1293. The source and claim
boundary findings remain unchanged: TFR-017 still blocks broad multi-node or
production cluster claims, and the deleted closeout notes are not current
policy, current spec, implementation status, release-readiness evidence, or
product authority.

### Forgejo-Era Cluster Design Root Consolidation (TFR-019 / #1638)

Issue #1638 removed the unreferenced imported cluster/admin, snapshot,
mmap-coherency, and metadata-resilience roots:
`docs/design/admin-service-wire-protocol.md`,
`docs/design/cluster-admin-proxy-model.md`,
`docs/design/cluster-wide-atomic-snapshot-coordination.md`,
`docs/design/mmap-cluster-coherency.md`, and
`docs/design/metadata-redundancy-fallback.md`. Their lineage remains in git,
issue #1638, and its pull request only.

Issue #1699 later removed the remaining source- or doc-referenced
Forgejo-era cluster design roots from this family after moving the narrow
comment lineage into source-owned comments and current authority references.
Their lineage remains in git, issue #1699, and the pull request only. Current
transport, membership, operator-authz, clustered-lock boundary, source,
validation-claim, generated-claim, and live GitHub issue/PR authority remains
unchanged. This deletion does not promote distributed mode, clustered POSIX,
RDMA, mmap coherency, metadata redundancy, release readiness, production
readiness, OpenZFS/Ceph parity, or successor/comparator wording.

### Erasure Placement Historical Root Deletion (TFR-019 / #1702)

Issue #1702 deleted the imported erasure-placement design roots after replacing
the remaining live references with current pool-wide placement, placement
receipt, and source-backed EC-store authority references. Their lineage remains
in git, issue #1702, and its pull request only. Current authority remains with
`docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md`,
`docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`,
`docs/ERASURE_CODED_STORE_AUTHORITY.md`, source behavior, validation claims,
and live GitHub issues/PRs. This deletion does not promote production
erasure-coding placement, recovery-loop completion, rebalance performance,
distributed availability, release readiness, OpenZFS/Ceph parity, or
successor/comparator wording.

### Erasure Layout OW Note Deletion (TFR-019 / #1914)

Issue #1914 deleted `docs/ERASURE_CODED_LAYOUT_OW306.md` after folding the
bounded single-parity XOR layout boundary into
`docs/ERASURE_CODED_STORE_AUTHORITY.md` and retargeting
`check-erasure-coded-layout` away from the standalone OW note. Its lineage
remains in git, issue #1914, and its pull request only. Current authority
remains with `crates/tidefs-replication-model`,
`docs/ERASURE_CODED_STORE_AUTHORITY.md`, `check-erasure-coded-layout`,
validation claims, and live GitHub issues/PRs. This deletion does not promote
production erasure-coding placement, distributed rebuild/runtime,
kernel/block-device erasure coding, release readiness, OpenZFS/Ceph parity, or
successor/comparator wording.
