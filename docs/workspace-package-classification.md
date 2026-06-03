# Workspace Package Classification

> Review debt TFR-002/TFR-019: this document is stale review input, not current
> package authority. The root member list and Cargo now agree on 148 resolved
> workspace members, while this document still contains closed-gate wording and
> old 144-member counts. Use `docs/WHOLE_REPO_REVIEW.md` and
> `docs/REVIEW_TODO_REGISTER.md` until this classification is regenerated.
> Current 2026-06-01 metadata no longer reports direct scaffold dependencies
> from the POSIX daemon, POSIX core, POSIX schema codec, or `tidefs-xtask`;
> remaining direct control-plane type edges are publication-pipeline types,

Generated: 2026-05-18
Updated: 2026-05-24 (OWNER-RC-004 workspace product-authority gate closed, #6554)
Authority: Issue #5816, review-workspace-authority-stage, OWNER-RC-004

## Status Update (2026-05-24)

The workspace product-authority gate is closed (#6554). `cargo run -q -p
tidefs-xtask -- check-workspace-policy` passes against current master (144
workspace members, 502 internal dependency edges checked). The checker now
defaults unknown library crate classes to Core instead of Unknown, includes
root-level crate directories (kmod/) in member discovery, filters edge
checking to only actual workspace members, and properly classifies
`tidefs-cluster`, `tidefs-receive-*`, and `tidefs-policy-authority` (exact
ControlPlane-to-Test forbidden edge. Adapter worker suffix crates
(`-workers-io`, `-workers-locks`) are recognized as Core-class entries. The

The formal authority conflict between DESIGN_OVERFITTING_POLICY.md (May 11
cleanup era) and WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md
(production-depth workspace design) is resolved.  P1-01 is the controlling
workspace authority for scaffold-family crates.  The overfitting policy's
blanket removal directive is superseded where it conflicts with P1-01 family
assignments; it remains binding for micro-crate line-count rules, error-type
variant limits, feature-flag limits, dynamic-dispatch rules, concurrency
rules, and unsafe-code rules.

Scaffold crates are removed from the workspace members list, the
non-workspace control-plane-daemon and policy-authority-daemon directories
have been deleted, and `tidefs-local-filesystem/build.rs` enforces a
kernel-portability closure guard against `tidefs-types-control-plane-core`.
Remaining successor work (kmod workspace membership, zombie directory
cleanup, adapter micro-crate consolidation) is tracked on separate
implementation issues.

Scope: Every workspace member crate, app, and on-disk crate directory

This document classifies all TideFS Rust packages into six tiers:
remove-from-workspace. It also audits scaffold-to-production dependency
leakage and reconciles the May 11 cleanup-era DESIGN_OVERFITTING_POLICY.md
with the production-depth WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md.

## Classification Tiers

| Tier | Description |
|---|---|
| **production** | Core filesystem/storage behavior crate. Directly serves mounted POSIX or block I/O, or implements a required storage subsystem (intent log, checksums, allocation, namespace, scrub). |
| **adapter/harness** | Bridge crate connecting production to an external interface: FUSE daemon, ublk control, POSIX semantics, block volume projection. Also includes daemon app roots that wire adapter runtimes. |
| **remove-from-workspace** | Still in workspace members but classified as scaffold by overfitting policy and lacking production justification after P1-01 reconciliation. Should be removed from workspace members. |

## Dependency Leakage Audit

The following production/adapter crates depend on scaffold-family crates
(policy-authority, control-plane, response-registry, observe, truth-view,
shadow-pilot). Each finding includes justification or removal recommendation.

| Consumer | Scaffold Dependency | Severity | Resolution |
|---|---|---|---|
| `tidefs-local-filesystem` | `tidefs-types-control-plane-core` | **High** | Core storage should not depend on control-plane types. Inspect usage: if it's only type re-exports, inline or move to a neutral types crate. |
| `tidefs-posix-filesystem-adapter-daemon` | `tidefs-types-control-plane-core` | **Closed slice** | Current metadata no longer reports this direct dependency; the receipt-demo path now uses POSIX-local demo records and POSIX-local receipt ids. |
| `tidefs-posix-filesystem-adapter-daemon` | `tidefs-types-package-profile-catalog` | **Low** | Package profile catalog types are build/packaging metadata, not runtime scaffold. Acceptable if used for stage-binding queries only. |
| `tidefs-posix-filesystem-adapter-daemon` | `tidefs-types-publication-pipeline-core` | **Closed slice** | Current metadata no longer reports this direct dependency; the daemon demo path uses a local publication-ticket record. |
| `tidefs-posix-filesystem-adapter-daemon` | `tidefs-types-response-registry-core` | **Closed slice** | Current metadata no longer reports this direct dependency; the daemon demo path uses a local visible-answer record. |
| `tidefs-block-volume-adapter-daemon` | `tidefs-types-package-profile-catalog` | **Low** | Acceptable for stage-binding queries. |
| `tidefsctl` | `tidefs-control-plane-api` | **Expected** | tidefsctl is a control-plane CLI client. Per P1-01, this is the lawful dependency pattern for the operator CLI. |
| `tidefsctl` | `tidefs-control-plane-runtime` | **Expected** | tidefsctl wiring control-plane runtime. Per P1-01 app-root rule for tidefsctl. |
| `tidefsctl` | `tidefs-types-control-plane-core` | **Expected** | tidefsctl consuming control-plane types. Lawful. |

## Complete Package Classification

### Production

Core storage and filesystem behavior.

| Crate | Classification | Rationale |
|---|---|---|
| `tidefs-vfs-engine` | production | Central VFS dispatch engine. Production core. |
| `tidefs-local-filesystem` | production | Mounted filesystem implementation over local object store. Production core. |
| `tidefs-vfs-rpc` | production | VFS RPC types for cross-node VFS operations. Production core. |
| `tidefs-local-object-store` | production | Durable object store with segment files, replay, integrity checks. Production core. |
| `tidefs-intent-log` | production | Intent log for crash recovery replay. Production core. |
| `tidefs-namespace` | production | Directory entry and namespace management. Production core. |
| `tidefs-inode-table` | production | Inode allocation and lifecycle. Production core. |
| `tidefs-inode-attributes` | production | Inode attribute storage and retrieval. Production core. |
| `tidefs-extent-map` | production | File extent mapping (logical-to-physical). Production core. |
| `tidefs-block-allocator` | production | Block allocation for extent storage. Production core. |
| `tidefs-spacemap-allocator` | production | Free space tracking via spacemaps. Production core. |
| `tidefs-space-accounting` | production | Capacity accounting (used/free/reserved). Production core. |
| `tidefs-checksum-tree` | production | BLAKE3 content-addressed checksum tree. Production core. |
| `tidefs-scrub-core` | production | Checksum scrub verification and repair. Production core. |
| `tidefs-commit_group` | production | Transaction commit group coordination. Production core. |
| `tidefs-recovery-loop` | production | Mount-time recovery and intent replay. Production core. |
| `tidefs-reclaim` | production | Safe space reclamation with root retention. Production core. |
| `tidefs-segment-cleaner` | production | Segment cleaning and garbage collection. Production core. |
| `tidefs-snapshot-pruner` | production | Snapshot retention and pruning. Production core. |
| `tidefs-dir-index` | production | Directory index structures. Production core. |
| `tidefs-xattr-storage` | production | Extended attribute storage. Production core. |
| `tidefs-object-io` | production | Object I/O primitives. Production core. |
| `tidefs-btree` | production | B-tree implementation for on-disk structures. Production core. |
| `tidefs-binary_schema-core` | production | Binary schema encode/decode. Foundation layer. |
| `tidefs-binary_schema-checksum` | production | Checksummed binary schema framing. Foundation layer. |
| `tidefs-binary_schema-framing` | production | Binary schema frame delimiting. Foundation layer. |
| `tidefs-schema-codec-vfs` | production | VFS schema codec. Foundation layer. |
| `tidefs-schema-codec-posix-filesystem-adapter` | production | POSIX adapter schema codec. Foundation layer. |
| `tidefs-durability-layout` | production | Durability layout (mirror/erasure) placement. Production core. |
| `tidefs-erasure-coding` | production | Erasure coding computation. Production core. |
| `tidefs-erasure-coded-store` | production | Erasure-coded object store backend. Production core. |
| `tidefs-compression` | production | Data compression. Production core. |
| `tidefs-compaction` | production | Data compaction/defragmentation. Production core. |
| `tidefs-encryption` | production | At-rest encryption. Production core. |
| `tidefs-dedup` | production | Deduplication. Production core. |
| `tidefs-frame` | production | Record framing for storage I/O. Foundation layer. |
| `tidefs-gc-pin-set` | production | GC pin set tracking for safe reclamation. Production core. |
| `tidefs-locator-table` | production | Object locator table. Production core. |
| `tidefs-pool-allocator` | production | Pool-level allocation. Production core. |
| `tidefs-pool-import` | production | Pool import and discovery. Production core. |
| `tidefs-pool-scan` | production | Pool scanning. Production core. |
| `tidefs-flow-commit-coordinator` | production | Multi-phase commit coordination. Production core. |
| `tidefs-dataset-lifecycle` | production | Dataset lifecycle management. Production core. |
| `tidefs-dataset-catalog` | production | Dataset catalog and enumeration. Production core. |
| `tidefs-dataset-properties` | production | Dataset property management. Production core. |
| `tidefs-dataset-feature-flags` | production | Dataset feature flag enforcement. Production core. |
| `tidefs-derived-catalog` | production | Derived dataset catalog. Production core. |
| `tidefs-send-stream` | production | Send stream for replication. Production core. |
| `tidefs-receive-stream` | production | Receive stream for replication. Production core. |
| `tidefs-shard-group` | production | Shard group management. Production core. |
| `tidefs-replicated-object-store` | production | Replicated object store. Production core. |
| `tidefs-chunk-shipper` | production | Chunk shipping for data movement. Production core. |
| `tidefs-verification-engine` | production | Verification engine for received data. Production core. |
| `tidefs-quorum-write` | production | Quorum write coordination. Production core. |
| `tidefs-quorum-write-runtime` | production | Quorum write async runtime. Production core. |
| `tidefs-reserve-ledger` | production | Reserve ledger for space reservations. Production core. |
| `tidefs-claim-ledger` | production | Claim ledger for allocation claims. Production core. |
| `tidefs-witness-set` | production | Witness set for quorum decisions. Production core. |
| `tidefs-geometry-convert` | production | Geometry conversion for durability layouts. Production core. |
| `tidefs-background-scheduler` | production | Background task scheduler. Production core. |
| `tidefs-data-cleaner` | production | Background data cleaning. Production core. |
| `tidefs-cleanup-engine` | production | Cleanup job execution engine. Production core. |
| `tidefs-cleanup-job-core` | production | Cleanup job definitions. Production core. |
| `tidefs-cleanup-queue-core` | production | Cleanup queue management. Production core. |
| `tidefs-reclaim-queue-core` | production | Reclaim queue management. Production core. |
| `tidefs-incremental-job-core` | production | Incremental job framework. Production core. |
| `tidefs-cache-core` | production | Cache management core. Production core. |
| `tidefs-trace-oracle` | production | Trace oracle for access pattern detection. Production core. |
| `tidefs-online-defrag` | production | Online defragmentation. Production core. |
| `tidefs-orphan-index` | production | Orphan tracking and cleanup. Production core. |
| `tidefs-clock-timing` | production | Clock and timing primitives. Foundation layer. |
| `tidefs-anti-entropy-auditor` | production | Anti-entropy auditing. Production core. |
| `tidefs-auth` | production | Authentication and authorization. Production core. |
| `tidefs-permission` | production | Permission checking. Production core. |
| `tidefs-posix-acl` | production | POSIX ACL support. Production core. |
| `tidefs-posix-semantics` | production | POSIX semantics enforcement. Production core. |
| `tidefs-posix-guarantee-verifier` | production | POSIX guarantee verification. Production core. |
| `tidefs-secret-key-policy-runtime` | production | Secret key policy enforcement. Production core. |

### Adapter / Harness

Bridge crates and daemon apps connecting production core to external interfaces.

| Crate | Classification | Rationale |
|---|---|---|
| `tidefs-fuser` | adapter/harness | FUSE protocol library (fork of fuser). Adapter to Linux FUSE. |
| `tidefs-posix-filesystem-adapter-daemon` | adapter/harness | FUSE mount daemon. App root for POSIX filesystem adapter. |
| `fuser` | adapter/harness | Patched fuser dependency providing the FUSE protocol library. Adapter to Linux FUSE. |
| `tidefs-posix-filesystem-adapter-reply` | adapter/harness | FUSE reply attribute assembly. |
| `tidefs-posix-filesystem-adapter-workers-io` | adapter/harness | FUSE I/O worker. Under 1,000 lines; candidate for module consolidation. |
| `tidefs-posix-filesystem-adapter-workers-locks` | adapter/harness | FUSE lock worker. Under 1,000 lines; candidate for module consolidation. |
| `tidefs-block-volume-adapter-core` | adapter/harness | Block volume adapter core types and traits. |
| `tidefs-block-volume-adapter-ublk-control-runtime` | adapter/harness | ublk control runtime bridging to local filesystem. |
| `tidefs-block-volume-adapter-daemon` | adapter/harness | ublk block daemon. App root for block volume adapter. |
| `tidefs-ublk-abi` | adapter/harness | Linux ublk ABI constants and ioctl definitions. |
| `tidefs-schema-codec-control-plane` | adapter/harness | Control-plane schema codec. Adapter between control-plane and schema. |
| `tidefs-schema-codec-outcome` | adapter/harness | Outcome schema codec for policy/response surfaces. |
| `tidefsctl` | adapter/harness | Operator CLI for TideFS management. App root. |
| `tidefs-storage-node` | adapter/harness | Storage node daemon. App root for multi-node operation. |
| `tidefs-kmod-posix-vfs` | adapter/harness | Kernel module: POSIX VFS operations. Kernel adapter. |
| `tidefs-block-kmod` | adapter/harness | Kernel module: block device. Kernel adapter. |
| `tidefs-kmod-bridge` | adapter/harness | Kernel module bridge providing shared Rust-for-Linux contracts. Kernel adapter. |
| `tidefs-kmod-policy-authority` | adapter/harness | Kernel module: policy authority bridge. Kernel adapter. |
| `tidefs-kernel-cutover-runtime` | adapter/harness | Cutover runtime for kernel mode transition. |
| `tidefs-filesystem-demo` | adapter/harness | Demo binary. App root for demonstration. |
| `tidefs-store-demo` | adapter/harness | Demo binary for object store. App root. |
| `tidefs-scrub` | adapter/harness | Scrub CLI tool. App root. |
| `tidefs-pool-scan` | adapter/harness | Pool scanning with binary entry point. |



| Crate | Classification | Rationale |
|---|---|---|

### Experimental

Multi-node, membership, transport, placement, and rebuild crates under active
implementation. Classified as experimental because they lack deterministic

| Crate | Classification | Rationale |
|---|---|---|
| `tidefs-transport` | experimental | Multi-node transport with TCP/RDMA. Active implementation (#5787, #5788, #5789, #5790, #5793, #5795). |
| `tidefs-membership-epoch` | experimental | Membership epoch management. Active implementation. |
| `tidefs-membership-live` | experimental | Live membership with session binding and liveness. Active implementation (#5791, #5794). |
| `tidefs-membership-types` | experimental | Membership type definitions. |
| `tidefs-cluster` | experimental | Cluster lease state machine and runtime. Active implementation (#5768). |
| `tidefs-lease` | experimental | Lease management. Active implementation. |
| `tidefs-lease-manager` | experimental | Lease manager runtime. |
| `tidefs-node-join` | experimental | Node join protocol. |
| `tidefs-node-drain` | experimental | Node drain protocol. |
| `tidefs-partition-runtime` | experimental | Partition management runtime. |
| `tidefs-placement-planner` | experimental | Data placement planning. |
| `tidefs-placement-runtime` | experimental | Placement execution runtime. |
| `tidefs-replication` | experimental | Data replication. |
| `tidefs-replication-model` | experimental | Replication model and policy. |
| `tidefs-replica-health` | experimental | Replica health monitoring. |
| `tidefs-rebuild-planner` | experimental | Rebuild planning after failure. |
| `tidefs-rebuild-runtime` | experimental | Rebuild execution runtime. |
| `tidefs-rebalance-planner` | experimental | Rebalance planning. |
| `tidefs-relocation-planner` | experimental | Data relocation planning. |
| `tidefs-coordination-strategy` | experimental | Coordination strategy for distributed operations. |
| `tidefs-lock-service` | experimental | Distributed lock service. |
| `tidefs-tdma-scheduler` | experimental | TDMA scheduler for deterministic multi-node. |
| `tidefs-device-removal` | experimental | Device removal handling. Depended on by tidefs-pool-import via path dependency. Should be added to workspace members when its API stabilizes. |

### Scaffold / Remove-from-Workspace

Packages classified as scaffold by DESIGN_OVERFITTING_POLICY.md and lacking
a production role after P1-01 reconciliation. Should be removed from the
workspace members list.

| Crate | Classification | Rationale |
|---|---|---|
| `tidefs-policy-authority-client` | remove-from-workspace | Scaffold; overfitting policy target. No production consumer justifies workspace membership. |
| `tidefs-policy-authority-core` | remove-from-workspace | Scaffold; overfitting policy target. |
| `tidefs-policy-authority-runtime` | remove-from-workspace | Scaffold; overfitting policy target. |
| `tidefs-policy-authority-daemon` | remove-from-workspace | Scaffold daemon; overfitting policy target. App root with no production behavior. |
| `tidefs-control-plane-api` | remove-from-workspace | Scaffold; overfitting policy target. tidefsctl depends on this; dependency must be severed before removal. |
| `tidefs-control-plane-runtime` | remove-from-workspace | Scaffold; overfitting policy target. tidefsctl depends on this; dependency must be severed before removal. |
| `tidefs-control-plane-daemon` | remove-from-workspace | Scaffold daemon; overfitting policy target. App root with no production behavior. |
| `tidefs-response-registry-query` | remove-from-workspace | Scaffold; overfitting policy target. |
| `tidefs-response-registry-runtime` | remove-from-workspace | Scaffold; overfitting policy target. |
| `tidefs-observe-core-truth-view-render` | remove-from-workspace | Scaffold; overfitting policy target. |
| `tidefs-types-policy-authority-core` | deleted | Scaffold types; deleted from the fresh TideFS checkout after reverse-reference review found no live code consumers outside stale docs/xtask classifier fixtures. Current policy-authority record surfaces live in `tidefs-types-vfs-core`. |
| `tidefs-types-publication-pipeline-core` | remove-from-workspace | Scaffold types; overfitting policy target. Current metadata reports zero direct workspace consumers; inspect before removal. |
| `tidefs-types-response-registry-core` | remove-from-workspace | Scaffold types; overfitting policy target. Current metadata reports zero direct workspace consumers; inspect before removal. |
| `tidefs-types-observe-core` | deleted | Scaffold types; block daemon dependency was replaced with local host/kernel classification, and current observe/truth-view record surfaces live in `tidefs-types-vfs-core`. |
| `tidefs-types-truth-view-core` | deleted | Scaffold types; current truth-view records live in `tidefs-types-vfs-core`. |
| `tidefs-types-shadow-pilot` | deleted | Orphan scaffold model with zero live code consumers. |
| `tidefs-types-archive-control-core` | deleted | Scaffold types; current archive-control record surfaces live in `tidefs-types-vfs-core`. |
| `tidefs-posix-filesystem-adapter-runtime` | deleted | Zero-reverse adapter/runtime crate with hard scaffold type dependencies. The live runtime module is `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/mod.rs`. |

### Archived (Zombie Directories)

On-disk crate directories with Cargo.toml but NOT in workspace members.
Leftovers from consolidation (#5725). Moved to archive/crates/ as of 2026-05-18.

2026-06-01 update: no POSIX adapter zombie crate directories remain under
`crates/`. The already-absent `capacity`, `fusewire`, `ingress`, and
`scheduler` shards plus the restored `maintenance`, `workers-meta`,
`workers-ns`, and `workers-writeback` shards were all consolidated into the
adapter runtime by #5725; the restored four directories have now been deleted
instead of being kept as ambiguous live-looking crate roots. The active POSIX
adapter workspace surface is the daemon plus `runtime`, `reply`, `workers-io`,
`workers-locks`, and vendored `fuser`.

### Types Crates: Production Role

Types crates that serve the production core. These provide canonical type
definitions consumed by multiple production crates. Per P1-01, types family
(f0) is a lawful workspace family in stratum s0.

| Crate | Classification | Rationale |
|---|---|---|
| `tidefs-types-vfs-core` | production | VFS core types consumed by vfs-engine. Foundation layer. |
| `tidefs-types-vfs-owned` | production | Owned VFS value types. Foundation layer. |
| `tidefs-types-package-profile-catalog` | production | Package profile catalog types for stage binding. Foundation layer. |
| `tidefs-types-posix-filesystem-adapter-core` | production | POSIX adapter core types consumed by adapter daemon and runtime. |
| `tidefs-types-cache-lattice-core` | production | Cache lattice types consumed by cache-core. |
| `tidefs-types-reclaim-queue-core` | production | Reclaim queue types consumed by reclaim and reclaim-queue-core. |
| `tidefs-types-dataset-feature-flags-core` | production | Dataset feature flag types consumed by dataset-feature-flags. |
| `tidefs-types-dataset-lifecycle-core` | production | Dataset lifecycle types consumed by dataset-lifecycle. |
| `tidefs-types-polymorphic-directory-index-core` | production | Directory index polymorphism types consumed by dir-index. |
| `tidefs-types-polymorphic-xattr-core` | production | Xattr polymorphism types consumed by xattr-storage. |
| `tidefs-types-extent-map-core` | production | Extent map types consumed by extent-map. |
| `tidefs-types-secret-key-policy-core` | production | Secret key policy types consumed by secret-key-policy-runtime. |
| `tidefs-types-space-accounting-core` | production | Space accounting types consumed by space-accounting. |
| `tidefs-types-pool-label-core` | production | Pool label types consumed by pool-import. |
| `tidefs-types-claim-ledger-core` | production | Claim ledger types consumed by claim-ledger. |
| `tidefs-types-orphan-index-core` | production | Orphan index types consumed by orphan-index. |
| `tidefs-types-deferred-cleanup-core` | production | Deferred cleanup types consumed by cleanup crates. |
| `tidefs-types-incremental-job-core` | production | Incremental job types consumed by incremental-job-core. |
| `tidefs-types-transport-session` | production | Transport session types consumed by transport. |

## May 11 Overfitting Policy Reconciliation

### Background

DESIGN_OVERFITTING_POLICY.md (May 11 cleanup era) is labeled "binding on all
current and future TideFS code." It mandates:

1. Remove 20 named scaffold packages from the workspace.
2. Consolidate ~30 `tidefs-types-*` crates into consuming crates.
3. Merge 12 `tidefs-posix-filesystem-adapter-*` sub-crates into the daemon.
4. Error types must have at most 12 variants.
5. Feature flags at most 8 per crate.

P1-01 (workspace family layout, v0.362) establishes 12 workspace families
including policy_authority (f2), authority_publication (f3),
claim_reserve_witness (f4), response_normalizer (f5), control_plane (f8),
explanation_query (f9), and observe (f10) as lawful workspace families.

### Reconciliation Per Family

#### policy_authority family (f2)

- **Overfitting status**: Listed for removal (client, core, runtime, daemon,
  types-core).
- **P1-01 status**: Lawful workspace family f2 in stratum s1.
- **Current state**: All four crates plus types are in workspace. No production
  crate currently consumes policy-authority-client or policy-authority-core at
  runtime. The policy-authority-daemon is a bounded mirror app root with no
  production behavior.
- **Resolution**: **Superseded.** The overfitting policy's blanket removal is
  too aggressive. Per P1-01, policy_authority has a lawful home. However, the
  current crates have no production consumers and tests. They should remain in
  workspace but are classified as remove-from-workspace until they acquire a
  production consumer or are given explicit stage binding. P1-01 edge e3 allows
  policy_authority to depend on types/schema/authority_publication/
  claim_reserve_witness/response_normalizer but not on product adapters.

#### control_plane family (f8)

- **Overfitting status**: Listed for removal (api, runtime, daemon,
  types-control-plane-core).
- **P1-01 status**: Lawful workspace family f8 in stratum s3.
- **Current state**: tidefsctl depends on control-plane-api, control-plane-runtime,
  and types-control-plane-core. tidefs-local-filesystem depends on
  types-control-plane-core. These are real dependencies.
- **Resolution**: **Partially binding.** The overfitting policy's removal
  target is correct for control-plane-daemon (no production role) but
  premature for api/runtime/types because tidefsctl is a production operator
  CLI that needs them. Per P1-01, tidefsctl's dependency on control-plane is
  lawful. The types-control-plane-core dependency from local-filesystem
  is the one that violates scaffold boundaries and must be removed.

#### response_registry / response_normalizer (f5)

- **Overfitting status**: Listed for removal (query, runtime,
  types-response-registry-core).
- **P1-01 status**: Lawful workspace family f5 (response_normalizer) in
  stratum s1.
- **Current state**: FUSE daemon depends on types-response-registry-core.
  No production runtime consumer of response-registry-query or -runtime.
- **Resolution**: **Superseded.** Per P1-01, response_normalizer is a lawful
  family. The types crate may remain if FUSE daemon's response emission
  uses it. The query and runtime crates with no consumers should be removed.

#### observe family (f10)

  observe-truth-view-render, types-observe-core).
- **P1-01 status**: Lawful workspace family f10 in stratum s4.
- **Resolution**: **Superseded.** Per P1-01 edge e6, observe is a read-only
  surface that production adapters may depend on. The block daemon's
  dependency on observe types is lawful.

#### truth_view and shadow_pilot

- **Overfitting status**: Listed for removal (types-truth-view-core,
  types-shadow-pilot).
- **P1-01 status**: Not explicitly named as standalone families. truth_view
  maps to observe/explanation_query per P1-01.
- **Current state**: No production consumers. types-shadow-pilot was
  converted to no_std for K7-03.
- **Resolution**: **Still binding.** These crates have no production
  consumers and no P1-01 lawful home as standalone families. Remove.

### Micro-Crate Rule Reconciliation

The overfitting policy's rule "no crate under ~1,000 lines" conflicts with
P1-01's types family (f0), which explicitly allows small canonical type
crates. Resolution:

- **Superseded for types family (f0)**: Per P1-01, the types family in
  stratum s0 is a lawful home for canonical ids, scalars, enums, and small
  value objects. The line-count rule does not apply to types-* crates that
  serve as shared vocabulary for multiple production consumers.
- **Still binding for adapter sub-crates**: workers-io and workers-locks
  are under 1,000 lines and should be merged into the adapter runtime
  or daemon crate as modules.

### POSIX Adapter Sub-Crate Rule Reconciliation

- **Overfitting status**: All 12 sub-crates must be merged.
- **P1-01 status**: posix_filesystem_adapter (f6) is a single workspace
  family. P1-01 allows runtime/client/render crates within a family but
  discourages micro-crates.
- **Current state**: 8 of 12 sub-crates already removed from workspace
  (archived zombie directories). 4 remain: runtime, reply, workers-io,
  workers-locks.
- **Resolution**: **Mostly resolved.** The remaining sub-crates (reply,
  workers-io, workers-locks) should be merged into the daemon or runtime
  crate as modules. Reply is a legitimate standalone because it's shared
  between fuser (tidefs-fuser) and the daemon.

### Error Type and Feature Flag Rules

These are orthogonal to the workspace classification. They remain binding
design rules per the overfitting policy and are not affected by P1-01.

## kmod Workspace Membership

DESIGN_OVERFITTING_POLICY.md does not address kmod/. P1-01 rule 5.2 states:
`kmod/` is **not** a member of the main userspace Cargo workspace. However,
current Cargo.toml includes `kmod` as a workspace member.

**Resolution**: Per P1-01, `kmod` should be removed from the workspace
members list. The kmod crates compile under Kbuild against the Linux 7.0
kernel tree, not under Cargo. Keeping them in the Cargo workspace creates
unnecessary build graph edges.

## A-Register Findings

This document directly addresses A1 and A2 from the full-review-attention-register.md:

- **A1 (Documentation Authority Is Stale)**: This document establishes a
  single classification authority that reconciles two competing docs
  (overfitting policy vs. workspace family layout) for the specific
  question of workspace package status.
- **A2 (Workspace Shape Contradicts Cleanup Policy)**: This document
  resolves the contradiction by classifying every package, reconciling
  the May 11 directives with P1-01 for each affected family, and
  identifying the specific scaffold-to-production dependency edges that
  must be severed.

Status: A1 advanced. A2 advanced (authority conflict resolved by P1-01 as controlling authority). A1 not closed (requires stale doc refresh). A2 not closed (requires
actual workspace member list and dependency changes, not just
classification).


This deliverable is a classification/design record only. It is not release
RDMA, multi-node, performance, or kernel residency.

Required successor work to close A1/A2 (status as of 2026-05-21):
1. [ ] Remove `kmod` from workspace members per P1-01.
2. [x] Sever `tidefs-local-filesystem -> tidefs-types-control-plane-core` (build.rs guard enforces this).
3. [x] Remove the 20 scaffold packages from workspace members after severing
   all production dependencies.
4. [ ] Move archived zombie directories to `archive/` or delete them (partially done).
5. [ ] Merge workers-io and workers-locks into the adapter daemon runtime.
