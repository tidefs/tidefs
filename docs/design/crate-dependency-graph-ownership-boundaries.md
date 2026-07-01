# Crate Dependency Graph and Ownership Boundaries

**Issue**: [#2100](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2100)
**Status**: historical-input
**Priority**: P1
**Lane**: docs
**Kind**: documentation
**Last updated**: 2026-05-05

> **HISTORICAL DESIGN INPUT — NOT CURRENT AUTHORITY**
>
> This document is a stale snapshot of a historical workspace (177 crates,
> Forgejo issue #2100). Several type-root crates it references as active
> foundation types have been retired, consolidated, or deleted:
> `tidefs-types-control-plane-core`,
> `tidefs-types-response-registry-core`,
> `tidefs-types-publication-pipeline-core`,
> `tidefs-types-continuity-charter`,
> `tidefs-types-shadow-pilot`,
> `tidefs-types-locator-table-core`, and others.
>
> **Current authority**: [`docs/workspace-package-classification.md`](../workspace-package-classification.md)
> for the active package-role table, [`docs/WHOLE_REPO_REVIEW.md`](../WHOLE_REPO_REVIEW.md)
> for the current member set, and
> for the deleted type-root consolidation lineage. Use
> `docs/workspace-package-classification.md`, git history, and GitHub issue/PR
> lineage for the current rationale; use `cargo metadata --no-deps` for live
> dependency edges.
>
> TFR-002 / TFR-019 / issue #1019.

## Abstract

This is a **historical design document** that recorded the crate-level
dependency graph for a past TideFS Rust workspace snapshot. The deleted
type-root consolidation lineage now lives in git history and GitHub issue/PR
state; use `docs/workspace-package-classification.md` for current package
roles.
Do not cite its tables or dependency edges as current workspace authority.

The former 11-layer DESIGN issue matrix was deleted as stale Forgejo-era
coordination material. Git history and the associated GitHub issue/PR lineage
retain that path for archaeological review; live scheduling comes from GitHub
issues and pull requests, and current workspace structure comes from the
authority files above.

---

## 1. Crate Taxonomy

All 177 `tidefs-*` crates fall into five categories based on their role in the
dependency graph:

| Category | Count | Description | Naming Convention |
|----------|-------|-------------|-------------------|
| **Foundation Types** | 38 | `no_std`-compatible pure data types, wire formats, enums, newtypes | `tidefs-types-<domain>-core` |
| **Core Logic** | 12 | Pure algorithms, no I/O or async runtime, depends only on types | `tidefs-<domain>-core` |
| **Schema / Codec** | 11 | Binary encode/decode, framing, checksums, wire protocols | `tidefs-binary_schema-*`, `tidefs-schema-codec-*` |
| **Runtime / Daemon** | 38 | Async I/O, system services, daemon binaries, background workers | `tidefs-<domain>-runtime`, `tidefs-<domain>-daemon` |
| **Leaf Utilities** | 78 | Standalone crates with no tidefs dependencies (primitives, algorithms) | various (`tidefs-btree`, `tidefs-compression`, etc.) |

### 1.1 Dependency Direction Rule

Dependencies must flow **upward** through categories:

```
Foundation Types  ←  no tidefs deps (except other foundation types)
       ↑
Core Logic        ←  depends only on Foundation Types
       ↑
Schema / Codec    ←  depends on Foundation Types
       ↑
Runtime / Daemon  ←  depends on Core, Schema, Foundation Types
       ↑
Daemon Binaries   ←  depends on Runtime + everything below
```

**Cycles are forbidden.** The current workspace has zero cyclic dependencies.

---

## 2. Ownership Boundaries

> **HISTORICAL**: The crate inventory, dependency counts, and foundation-types
> table below reflect a past workspace snapshot. Several listed crates
> (`tidefs-types-control-plane-core`, `tidefs-types-response-registry-core`,
> `tidefs-types-publication-pipeline-core`, and others) have been retired or
> consolidated. See the document header for current authority pointers.

Each crate group "owns" a specific architectural concern. The ownership boundary
defines what a crate is allowed to contain and what it must delegate to
dependent crates.

### 2.1 Foundation Types Crates (`tidefs-types-*`)

**Ownership**: Canonical type definitions, enums, structs, traits, constants,
and wire-format layouts. These crates define *what* data looks like, not *how*
it is processed.

**Boundary rules**:
- Must be `#![no_std]` compatible (or explicitly opt out with justification).
- Must not contain I/O, async, allocation-heavy logic, or system calls.
- Must not depend on runtime crates.
- May depend on other foundation types crates.
- Must not contain algorithms — only type definitions and `const` assertions.

**Key foundation types crates** (foundational to many dependents):

| Crate | Owns | Used By |
|-------|------|---------|
| `tidefs-types-vfs-core` | InodeId, FileType, FileAttributes, VFS boundary types | 12+ crates |
| `tidefs-types-control-plane-core` | Control plane message envelope, node identity, session types | 20+ crates |
| `tidefs-types-incremental-job-core` | BackgroundJob, ServiceBudget, JobState, tick model | background scheduler, cleanup/reclaim jobs |
| `tidefs-types-extent-map-core` | ExtentMapEntry, ExtentState, tristate model | locator-table, space accounting |
| `tidefs-types-cache-lattice-core` | CacheKey, CacheEntry, unified cache lattice types | cache-core, adaptive-governor |
| `tidefs-types-orphan-index-core` | OrphanEntry, OrphanKind, namespace orphan tracking | orphan-index, orphan-recovery-job |
| `tidefs-types-pool-label-core` | PoolLabelV1 (411-byte wire format), PoolState, DeviceClass | local-object-store |
| `tidefs-types-posix-filesystem-adapter-core` | POSIX adapter boundary types | all POSIX adapter worker crates |
| `tidefs-types-response-registry-core` | Response envelope, registry key types | response-registry, control-plane |
| `tidefs-types-publication-pipeline-core` | Publication lifecycle types | authority-publication, policy-authority |
| `tidefs-types-reclaim-queue-core` | Reclaim queue entry types | reclaim-queue-core, reclaim-job-core |
| `tidefs-types-deferred-cleanup-core` | Deferred cleanup entry types | cleanup-queue-core, cleanup-job-core |
| `tidefs-types-claim-ledger-core` | Claim/allocate/commit entry types | claim-ledger, claim_reserve_witness-space-* |
| `tidefs-types-truth-view-core` | Truth view rendering surface types | observe-truth-view-render, control-plane-daemon |

### 2.2 Core Logic Crates (`tidefs-*-core`)

**Ownership**: Pure, deterministic algorithms operating on foundation types.
No I/O, no async, no system calls. These crates define *how* data is transformed.

**Boundary rules**:
- Must not perform I/O or spawn tasks.
- Must not depend on runtime crates.
- Must be deterministic given the same inputs.
- Must depend only on foundation types and other core crates.

| Crate | Owns | Key Algorithm |
|-------|------|---------------|
| `tidefs-block-volume-adapter-core` | Block volume dispatch logic, I/O descriptor handling | Block I/O request → queued operation mapping |
| `tidefs-cache-core` | Unified cache lattice insertion/eviction/coherency | Cache coherency state machine |
| `tidefs-cleanup-queue-core` | Deferred cleanup queue insertion/removal/ordering | BTree-based priority queue |
| `tidefs-cleanup-job-core` | Deferred cleanup job execution (IncrementalJob impl) | Background job tick with budget enforcement |
| `tidefs-incremental-job-core` | BackgroundJob trait, IncrementalJob runtime harness | Tick-driven job advancement |
| `tidefs-orphan-recovery-job-core` | Orphan recovery as background job | Namespace traversal + orphan detection |
| `tidefs-policy-authority-core` | Policy evaluation engine | Policy rule matching and composition |
| `tidefs-reclaim-queue-core` | Reclaim queue insertion/removal/ordering | BTree-based priority queue |
| `tidefs-reclaim-job-core` | Reclaim job execution (IncrementalJob impl) | Background job tick with budget enforcement |
| `tidefs-response-normalizer-core` | Response normalization logic | Canonical response formatting |
| `tidefs-authority-publication-core` | Authority publication lifecyle state machine | Publication stage advancement |
| `tidefs-explanation-query-core` | Explanation query evaluation | Query plan optimization |

### 2.3 Schema / Codec Crates (`tidefs-binary_schema-*`, `tidefs-schema-codec-*`)

**Ownership**: Binary encoding/decoding, framing, checksumming, and wire
protocol implementation.

**Boundary rules**:
- Must handle endianness explicitly.
- Must include checksum verification where applicable.
- Must not contain business logic — only encode/decode.

| Crate | Owns |
|-------|------|
| `tidefs-binary_schema-core` | Core binary schema traits, encoding primitives |
| `tidefs-binary_schema-checksum` | Checksum computation and verification over encoded data |
| `tidefs-binary_schema-framing` | Length-delimited framing, message boundary detection |
| `tidefs-schema-codec-vfs` | VFS operation encode/decode |
| `tidefs-schema-codec-vfs-boundary` | VFS boundary environment split encode/decode |
| `tidefs-schema-codec-control-plane` | Control plane message encode/decode |
| `tidefs-schema-codec-posix-filesystem-adapter` | POSIX adapter message encode/decode |

### 2.4 Runtime / Daemon Crates

**Ownership**: Async I/O, system service lifecycle, daemon binaries, background
worker execution, FUSE/uBLK adapters, transport sessions.

**Boundary rules**:
- May perform I/O, spawn tasks, manage threads.
- Must not be depended on by foundation types, core logic, or schema crates.
- Daemon crates are the top of the dependency graph.

#### POSIX Filesystem Adapter Family

| Crate | Owns |
|-------|------|
| `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` | Shared runtime module for POSIX adapter workers |
| `tidefs-posix-filesystem-adapter-workers-io` | I/O operation worker pool |
| `tidefs-posix-filesystem-adapter-workers-locks` | File locking worker pool |
| `tidefs-posix-filesystem-adapter-reply` | Reply construction and delivery |
| `tidefs-posix-filesystem-adapter-daemon` | Top-level daemon binary |

#### Control Plane Family

| Crate | Owns |
|-------|------|
| `tidefs-control-plane-api` | Control plane API definitions |
| `tidefs-control-plane-runtime` | Control plane service runtime |
| `tidefs-control-plane-daemon` | Control plane daemon binary |

#### Policy Authority Family

| Crate | Owns |
|-------|------|
| `tidefs-policy-authority-client` | Policy authority client library |
| `tidefs-policy-authority-core` | Policy evaluation engine (core) |
| `tidefs-policy-authority-runtime` | Policy authority service runtime |
| `tidefs-policy-authority-daemon` | Policy authority daemon binary |

#### Response Registry Family

| Crate | Owns |
|-------|------|
| `tidefs-response-registry-query` | Response registry query interface |
| `tidefs-response-registry-runtime` | Response registry service runtime |

#### Block Volume Adapter Family

| Crate | Owns |
|-------|------|
| `tidefs-block-volume-adapter-core` | Block volume dispatch and I/O descriptor logic |
| `tidefs-block-volume-adapter-ublk-control-runtime` | uBLK control plane runtime |
| `tidefs-block-volume-adapter-daemon` | Block volume daemon binary |

#### Observability Family

| Crate | Owns |
|-------|------|
| `tidefs-observe-core-runtime` | Observation runtime |
| `tidefs-observe-core-truth-view-render` | Truth view rendering |
| `tidefs-observe-cored` | Observation trait definitions |

#### Cluster / Distributed Family

| Crate | Owns |
|-------|------|
| `tidefs-transport` | Transport/session layer (P8-01 endpoint lifecycle) |
| `tidefs-membership-epoch` | Cluster membership epoch management |
| `tidefs-membership-live` | Live membership state tracking |
| `tidefs-membership-types` | Membership type definitions |
| `tidefs-cluster-gc` | Cluster-wide garbage collection |
| `tidefs-cluster-snapshot` | Cluster-wide snapshot coordination |
| `tidefs-bootstrap` | Cluster bootstrap protocol |
| `tidefs-node-join` | Node join protocol |
| `tidefs-node-drain` | Node drain protocol |
| `tidefs-lease` | Distributed lease management |
| `tidefs-flow-commit-coordinator` | Flow commit coordination |
| `tidefs-chunk-shipper` | Cross-node chunk shipping |
| `tidefs-replica-health` | Replica health tracking |
| `tidefs-replication-model` | Replication topology model |
| `tidefs-replication` | Replication protocol |
| `tidefs-anti-entropy-auditor` | Anti-entropy audit service |
| `tidefs-quorum-write` | Quorum write protocol (core) |
| `tidefs-quorum-write-runtime` | Quorum write protocol (runtime) |
| `tidefs-placement-planner` | Data placement planning |
| `tidefs-placement-runtime` | Data placement runtime |
| `tidefs-rebuild-planner` | Rebuild planning |
| `tidefs-rebalance-planner` | Rebalance planning |
| `tidefs-relocation-planner` | Relocation planning |
| `tidefs-partition-runtime` | Partition management runtime |
| `tidefs-witness-set` | Witness set management |
| `tidefs-bulk-service` | Bulk data transfer service |
| `tidefs-distributed-storage-runtime` | Distributed storage runtime |
| `tidefs-recovery-loop` | Distributed recovery loop |

### 2.5 Leaf Utility Crates

**Ownership**: Standalone primitives, data structures, and algorithms with no
tidefs-specific dependencies. These are the foundation of the dependency graph.

| Crate | Owns |
|-------|------|
| `tidefs-btree` | B-Tree data structure |
| `tidefs-compression` | Compression algorithms |
| `tidefs-encryption` | Encryption primitives |
| `tidefs-erasure-coding` | Erasure coding algorithms |
| `tidefs-frame` | Frame allocation and management |
| `tidefs-format-identity` | Format identity constants |
| `tidefs-spacemap-allocator` | Spacemap-based block allocator |
| `tidefs-pool-allocator` | Pool-level allocator (depends on spacemap-allocator) |
| `tidefs-clock-timing` | Clock and timing utilities |
| `tidefs-posix-acl` | POSIX ACL evaluation |
| `tidefs-posix-semantics` | POSIX filesystem semantics |
| `tidefs-auth` | Authentication primitives |
| `tidefs-reclaim` | Reclaim utilities |
| `tidefs-semantic-op-registry` | Semantic operation registry |
| `tidefs-ublk-abi` | uBLK ABI bindings |
| `tidefs-dir-index` | Directory index |
| `tidefs-extent-map` | Extent map data structure |
| `tidefs-locator-table` | Locator table data structure |
| `tidefs-orphan-index` | Orphan index data structure |
| `tidefs-xattr-storage` | Extended attribute storage |
| `tidefs-gc-pin-set` | GC pin set management |
| `tidefs-secret-key-policy-runtime` | Secret key policy runtime |
| `tidefs-shadow-pilot-runtime` | Shadow pilot runtime |
| `tidefs-upgrade-runbook` | Upgrade runbook |
| `tidefs-online-verifier` | Online verifier |
| `tidefs-verification-engine` | Verification engine |
| `tidefs-test-harness` | Test harness utilities |
| historical chaos-campaign package | Chaos testing campaign (no current package) |
| `tidefs-stress` | Stress testing utilities |
| `tidefs-trace-oracle` | Deterministic trace oracle |
| `tidefs-dataset-feature-flags` | Dataset feature flags runtime |
| `tidefs-dataset-lifecycle` | Dataset lifecycle management |
| `tidefs-adaptive-governor` | Adaptive resource governor |
| `tidefs-erasure-coded-store` | Erasure coded object store |
| `tidefs-replicated-object-store` | Replicated object store |

---

> **HISTORICAL**: The dependency graph below reflects a past workspace
> snapshot. Many referenced crates no longer exist or have been consolidated.
> See the document header for current authority pointers.

## 3. Dependency Graph by Layer (Depth)

Crates are organized into dependency depth layers. Layer 1 crates have no
tidefs dependencies. Higher layers build on lower layers.

### Layer 1: Foundation (48 leaf crates with zero tidefs deps)

All `tidefs-types-*` leaf crates plus utility crates:

`tidefs-auth`, `tidefs-binary_schema-core`, `tidefs-block-volume-adapter-core`,
`tidefs-btree`, `tidefs-clock-timing`, `tidefs-erasure-coding`,
`tidefs-explanation-query-api`, `tidefs-explanation-query-client`,
`tidefs-explanation-query-core`, `tidefs-explanation-query-daemon`,
`tidefs-explanation-query-runtime`, `tidefs-format-identity`, `tidefs-frame`,
`tidefs-membership-epoch`, `tidefs-membership-types`, `tidefs-observe-core-runtime`,
`tidefs-observe-cored`, `tidefs-posix-acl`, `tidefs-posix-semantics`,
`tidefs-quorum-write`, `tidefs-reclaim`, `tidefs-response-normalizer-api`,
`tidefs-response-normalizer-core`, `tidefs-response-normalizer-runtime`,
`tidefs-semantic-op-registry`, `tidefs-spacemap-allocator`, `tidefs-stress`,
`tidefs-types-admin-service-core`,
`tidefs-types-continuity-charter`, `tidefs-types-control-plane-core`,
`tidefs-types-dataset-feature-flags-core`, `tidefs-types-dataset-lifecycle-core`,
`tidefs-types-extent-map-core`, `tidefs-types-incremental-job-core`,
`tidefs-types-package-profile-catalog`, `tidefs-types-polymorphic-directory-index-core`,
`tidefs-types-polymorphic-xattr-core`, `tidefs-types-pool-label-core`,
`tidefs-types-reclaim-queue-core`, `tidefs-types-shadow-pilot`,
`tidefs-types-space-accounting-core`, `tidefs-types-transport-session`,
`tidefs-types-type-map`, `tidefs-types-vfs-core`, `tidefs-types-workspace-layout`,
`tidefs-ublk-abi`

### Layer 2: Types with light deps

`tidefs-types-cache-lattice-core` → `tidefs-types-vfs-core`
`tidefs-types-vfs-owned` → `tidefs-types-vfs-core`
`tidefs-types-locator-table-core` → `tidefs-types-extent-map-core`
`tidefs-types-deferred-cleanup-core` → `tidefs-types-dataset-feature-flags-core`

### Layer 3: Schema codec foundations

`tidefs-binary_schema-checksum` → `tidefs-binary_schema-core`
`tidefs-binary_schema-framing` → `tidefs-binary_schema-checksum`, `tidefs-binary_schema-core`
`tidefs-schema-codec-vfs` → `tidefs-types-vfs-core`
`tidefs-schema-codec-vfs-boundary` → `tidefs-types-vfs-core`
`tidefs-schema-codec-control-plane` → `tidefs-types-control-plane-core`

### Layer 4: Types with moderate deps

`tidefs-types-claim-ledger-core` → `tidefs-types-control-plane-core`, `tidefs-types-vfs-core`
`tidefs-types-archive-control-core` → `tidefs-types-control-plane-core`
`tidefs-types-observe-core` → `tidefs-types-control-plane-core`
`tidefs-types-policy-authority-core` → `tidefs-types-control-plane-core`
`tidefs-types-posix-filesystem-adapter-core` → `tidefs-types-control-plane-core`
`tidefs-types-pressure-core` → `tidefs-types-cache-lattice-core`
`tidefs-types-publication-pipeline-core` → `tidefs-types-control-plane-core`
`tidefs-types-response-registry-core` → `tidefs-types-control-plane-core`
`tidefs-types-seam-core` → `tidefs-types-control-plane-core`
`tidefs-types-secret-key-policy-core` → `tidefs-types-control-plane-core`
`tidefs-types-truth-view-core` → `tidefs-types-control-plane-core`, `tidefs-types-response-registry-core`
`tidefs-types-zero-copy-pin-core` → `tidefs-types-cache-lattice-core`, `tidefs-types-vfs-core`

### Layer 5–7: Core logic and schema composition

`tidefs-schema-codec-outcome` → 8 types crates
`tidefs-schema-codec-posix-filesystem-adapter` → `tidefs-types-control-plane-core`, `tidefs-types-posix-filesystem-adapter-core`

`tidefs-cache-core` → `tidefs-types-cache-lattice-core`
`tidefs-incremental-job-core` → `tidefs-types-incremental-job-core`
`tidefs-cleanup-queue-core` → `tidefs-btree`, `tidefs-types-deferred-cleanup-core`
`tidefs-reclaim-queue-core` → `tidefs-btree`, `tidefs-types-reclaim-queue-core`
`tidefs-cleanup-job-core` → `tidefs-cleanup-queue-core`, `tidefs-types-deferred-cleanup-core`, `tidefs-types-incremental-job-core`
`tidefs-reclaim-job-core` → `tidefs-reclaim-queue-core`, `tidefs-types-incremental-job-core`, `tidefs-types-reclaim-queue-core`
`tidefs-orphan-recovery-job-core` → `tidefs-orphan-index`, `tidefs-types-incremental-job-core`, `tidefs-types-orphan-index-core`

### Layer 8+: Runtime and daemon crates

Runtime crates compose core logic, schema, and types into working services.
Daemon crates sit at the top, composing runtimes into standalone binaries.

Key high-level daemons:
- `tidefs-posix-filesystem-adapter-daemon` — depends on 16 tidefs crates (largest fan-in)
- `tidefs-control-plane-daemon` — depends on 11 tidefs crates
- `tidefs-policy-authority-daemon` — depends on 10 tidefs crates
- `tidefs-block-volume-adapter-daemon` — depends on 7 tidefs crates

---

## 4. Serial Write Surfaces

Per the parallel safety rules in AGENTS.md, these files may only be edited by
one active issue at a time:

| Surface | Path | Rule |
|---------|------|------|
| Local filesystem | `crates/tidefs-local-filesystem/src/lib.rs` | One active issue at a time |
| Local object store | `crates/tidefs-local-object-store/src/lib.rs` | One active issue at a time |

### 4.1 High Fan-Out Crates (coordination-sensitive)

> **HISTORICAL**: The fan-out counts and crate names below reflect a past
> workspace snapshot. Several listed crates are retired.

Crates with many dependents require extra care when changing their public API:

| Crate | Dependent Count | Change Impact |
|-------|-----------------|---------------|
| `tidefs-types-control-plane-core` | 20+ | Breaking change affects control plane, policy, observe, POSIX adapter families |
| `tidefs-types-vfs-core` | 12+ | Breaking change affects VFS engine, POSIX adapter, cache, claim families |
| `tidefs-types-incremental-job-core` | 5+ | Breaking change affects background scheduler, cleanup/reclaim jobs |
| `tidefs-types-cache-lattice-core` | 4+ | Breaking change affects cache-core, adaptive-governor, pressure, zero-copy-pin |

---

## 5. Crate Naming Convention

All crates follow the `tidefs-<domain>-<role>` pattern:

| Role Suffix | Meaning | Example |
|-------------|---------|---------|
| `-core` (types) | `no_std` type definitions, wire formats | `tidefs-types-vfs-core` |
| `-core` (logic) | Pure algorithms, no I/O | `tidefs-cleanup-queue-core` |
| `-runtime` | Async runtime, system integration | `tidefs-control-plane-runtime` |
| `-daemon` | Top-level binary crate | `tidefs-policy-authority-daemon` |
| `-api` | Public API surface | `tidefs-control-plane-api` |
| `-client` | Client library | `tidefs-policy-authority-client` |
| `-query` | Query interface | `tidefs-response-registry-query` |
| (no suffix) | Standalone utility or algorithm | `tidefs-btree` |

---

## 6. Dependency Invariants

The following invariants are enforced by `cargo check --workspace` and must
be preserved by all changes:

1. **No cycles.** The dependency graph is a DAG.
2. **No `types-*` → `runtime` deps.** Foundation type crates must not depend on
   runtime crates.
3. **No `core` → `runtime` deps.** Core logic crates must not depend on runtime
   crates.
4. **No `schema` → `runtime` deps.** Schema/codec crates must not depend on
   runtime crates.
5. **`tidefs-local-filesystem` and `tidefs-local-object-store` are serial
   write surfaces.** Only one active issue may edit each at a time.
6. **Daemon crates are leaf nodes.** No crate may depend on a daemon crate.

---

## 7. Relationship to Historical DESIGN Issue Matrix

> **HISTORICAL**: The layer-to-crate mapping below is a past snapshot. Several
> referenced crates (`tidefs-types-locator-table-core` and others) no longer
> exist.

In the same historical snapshot, a now-deleted 11-layer DESIGN issue matrix
recorded issue-level sequencing for 71 DESIGN issues across 4 milestones. The
crate graph documented here is the *historical implementation* artifact that
realized those designs in Rust at the time of writing. This section is not
current GitHub scheduling authority or current product architecture policy.

| DESIGN Layer | Primary Crates |
|-------------|----------------|
| L0 (Format Architecture) | `tidefs-format-identity`, `tidefs-binary_schema-*` |
| L1 (On-Media Storage) | `tidefs-types-extent-map-core`, `tidefs-types-locator-table-core`, `tidefs-extent-map`, `tidefs-locator-table`, `tidefs-spacemap-allocator`, `tidefs-pool-allocator` |
| L2 (Transaction Model) | `tidefs-local-object-store`, `tidefs-types-claim-ledger-core`, `tidefs-claim-ledger`, `tidefs-claim_reserve_witness-space-*` |
| L3 (VFS Engine) | `tidefs-types-vfs-core`, `tidefs-vfs-engine`, `tidefs-local-filesystem`, `tidefs-orphan-index`, `tidefs-dataset-lifecycle` |
| L4 (Background Services) | `tidefs-types-incremental-job-core`, `tidefs-incremental-job-core`, `tidefs-background-scheduler`, `tidefs-cleanup-*`, `tidefs-reclaim-*` |
| L5 (Coherency + Tiering) | `tidefs-types-cache-lattice-core`, `tidefs-cache-core`, `tidefs-adaptive-governor` |
| L6 (Data Services) | `tidefs-compression`, `tidefs-encryption`, `tidefs-erasure-coding` |
| L7 (Integrity Services) | `tidefs-online-verifier`, `tidefs-verification-engine`, `tidefs-replica-health`, `tidefs-anti-entropy-auditor` |
| L8 (Cluster Simnet) | `tidefs-test-harness`, historical chaos-campaign package, `tidefs-trace-oracle` |
| L9 (Cluster Coordination) | `tidefs-membership-*`, `tidefs-bootstrap`, `tidefs-node-*`, `tidefs-lease`, `tidefs-cluster-gc`, `tidefs-cluster-snapshot` |
| L10 (Cluster Data Plane) | `tidefs-transport`, `tidefs-chunk-shipper`, `tidefs-block-volume-*`, `tidefs-bulk-service`, `tidefs-distributed-storage-runtime`, `tidefs-flow-commit-coordinator` |
| L11 (Cross-cutting) | `tidefs-posix-filesystem-adapter-*`, `tidefs-control-plane-*`, `tidefs-policy-authority-*`, `tidefs-observe-core-*`, `tidefs-schema-codec-*` |

---

## 8. State and Maintenance

- **Current status**: historical-input (classified 2026-06-22 per issue #1019).
  This document is no longer regenerated and must not be cited as workspace
  authority.
- The original Forgejo issue #2100 tracked the creation of this document in a
  prior workspace; it is closed history.
- **Current authority for package classification**:
  [`docs/workspace-package-classification.md`](../workspace-package-classification.md)
  (enforced by `cargo run -p tidefs-xtask -- check-workspace-policy`).
- **Current authority for the workspace member set**:
  [`docs/WHOLE_REPO_REVIEW.md`](../WHOLE_REPO_REVIEW.md) and live
  `cargo metadata --no-deps`.
- **Consolidation rationale**: deleted type-root lineage lives in git history,
  GitHub issue/PR state, and the current package-role table.
- The former 11-layer DESIGN issue matrix was deleted instead of kept as
  another stale status surface; use git history and GitHub issue/PR lineage for
  archaeological review.
- The `crates/README.md` provides a human-readable index of active crate groups;
  consult it for current structure.
