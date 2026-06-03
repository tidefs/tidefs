# TideFS Workspace Structure

## Types-Core Layer

The types-core layer sits at the bottom of the TideFS dependency graph. This
document is historical review input; current package authority is
`cargo metadata --no-deps` plus `docs/WHOLE_REPO_REVIEW.md`.

### Architecture

The types-core layer is anchored by two hub crates:

- **tidefs-types-control-plane-core** (13 consumers, 2,135 lines): Control-plane
  identifiers, digests, policy recipes, and receipt types. Serves as the
  dependency root for 10 other types-core crates and 13 non-types crates
  including the FUSE adapter stack, secret-key-policy, and schema codecs.
  **Note**: this crate is classified as product-transitional scaffold in
  `docs/ARCHITECTURE.md`; it is in the workspace only because workspace
  members still depend on it.

- **tidefs-types-vfs-core** (21 consumers, 8,118 lines): VFS inode identifiers,
  generation counters, node kinds, extent descriptors, and filesystem constants.
  Serves 3 types-core crates and 18 non-types crates including the local
  filesystem, kmod bridge, block allocator, and namespace.

All types-core crates are `no_std` and depend only on other types-core crates
plus external crates (`core`, `alloc`, `serde`). No types-core crate depends
upward on a non-types `tidefs-*` crate.

### Dependency Graph

```
tidefs-types-control-plane-core ─────────────────────────────
  ├── tidefs-types-claim-ledger-core ─── also → vfs-core
  ├── tidefs-types-posix-filesystem-adapter-core
  ├── tidefs-types-publication-pipeline-core
  ├── tidefs-types-response-registry-core
  └── tidefs-types-secret-key-policy-core

tidefs-types-vfs-core ───────────────────────────────────────
  ├── tidefs-types-cache-lattice-core
  ├── tidefs-types-claim-ledger-core ─── also → control-plane-core
  └── tidefs-types-vfs-owned

The old archive-control, observe, policy-authority, truth-view, and
shadow-pilot split crates were deleted from the fresh TideFS checkout after
reverse-reference review. Their surviving record surfaces live in
`tidefs-types-vfs-core` or product-local modules.

Independent (no types-core deps):
  tidefs-types-continuity-charter
  tidefs-types-dataset-feature-flags-core
  │    └── tidefs-types-deferred-cleanup-core
  tidefs-types-dataset-lifecycle-core
  tidefs-types-extent-map-core
  tidefs-types-incremental-job-core
  tidefs-types-orphan-index-core
  tidefs-types-package-profile-catalog
  tidefs-types-polymorphic-directory-index-core
  tidefs-types-polymorphic-xattr-core
  tidefs-types-pool-label-core
  tidefs-types-reclaim-queue-core
  tidefs-types-space-accounting-core
  tidefs-types-transport-session
```

### Crate Justifications

Each remaining types-core split exists because the types serve multiple
heterogeneous consumers that would not benefit from inlining.

**Hub crates** (control-plane-core, vfs-core): Foundation types used by 20+
consumers across the entire stack. Must remain separate as the bottom of the
dependency graph.

**Domain crates** (3-8 consumers): Each represents a coherent bounded context:
pool labels for device/pool management, extent maps for block allocation,
incremental jobs for background work scheduling, reclaim queues for space
reclamation, dataset lifecycle/flags for dataset management, POSIX adapter
types for the FUSE surface, and publication pipeline types for commit
orchestration.

**Transport-session**: The only 2-consumer crate that remains justified because
its consumers (tidefs-transport and tidefs-replicated-object-store) sit at
different stack layers; folding would create an undesirable dependency
direction.

### Consolidation Status

A consolidation review ([types-core-consolidation-plan.md](types-core-consolidation-plan.md))
identified 3 dead splits, 1 orphan, and 4 near-dead splits. The plan
recommends removing 7 crates through phased implementation issues.

Executed consolidations:
- #5939: Merged tidefs-policy-authority client-core-runtime triplication into
  tidefs-policy-authority (separate issue, in progress).

Pending (see consolidation plan):
- Fold 3 single-consumer dead splits into their consumers
- Review remaining near-dead splits against current Cargo metadata before
  deciding whether to fold, keep, or delete them.
