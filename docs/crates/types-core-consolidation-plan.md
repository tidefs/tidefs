# TideFS Types-Core Crate Consolidation Plan

Integration review of `tidefs-types-*-core` single-file zero-test crates.
Issue: [#5943](https://forgejo/forgeadmin/tidefs/issues/5943)
Date: 2026-05-18

## Document Classification

This file is **historical consolidation evidence**, not current package
authority.  It records the 2026-05-18 inventory, analysis, and consolidation
plan that drove the 2026-06-01 type-root deletions.  Several crate roots it
names (`tidefs-types-archive-control-core`, `tidefs-types-observe-core`,
`tidefs-types-policy-authority-core`, `tidefs-types-shadow-pilot`,
`tidefs-types-truth-view-core`, `tidefs-schema-codec-outcome`) no longer
exist in the TideFS checkout.  Consumer counts, table rows, and the
Before/After projections below are snapshots of the workspace at that time.

Current package authority lives in
[`docs/workspace-package-classification.md`](/docs/workspace-package-classification.md).
Do not read this file as a live work plan or active type-root register.

**Freshness note (2026-06-01)**: This plan was written against
an earlier workspace snapshot. The five non-workspace types crate roots on
disk (`tidefs-types-archive-control-core`, `tidefs-types-observe-core`,
`tidefs-types-policy-authority-core`, `tidefs-types-shadow-pilot`, and
`tidefs-types-truth-view-core`) have now been deleted from the fresh TideFS
checkout after reverse-reference review. Specific consumer counts below are
historical review input; use `cargo metadata --no-deps` and
`docs/WHOLE_REPO_REVIEW.md` for current numbers.

## Methodology

Every types-core crate in the workspace was classified using four data sources:

1. `cargo metadata --no-deps` for forward and reverse dependency edges.
2. Direct `Cargo.toml` inspection for dependency direction and layering.
3. `rg` across the full workspace `Cargo.toml` surface to catch dev-dependency
   references that `cargo metadata` omits.
4. `workspace Cargo.toml` member lists to confirm which crates are active.

A crate is a **dead split** when it has exactly one non-types consumer and zero
types consumers. An **orphan** has zero consumers and is not a workspace member.
A **near-dead split** has exactly two consumers. **Layering violation** means
a types-core crate depends on a non-types `tidefs-*` crate (upward dependency).

The existing #5939 consolidation of `tidefs-types-policy-authority-core` is
acknowledged and deferred; this plan does not duplicate that work.

## Inventory

29 types-core crates were identified. All have `src=1`, `test=1` (inline
`#[cfg(test)]` modules within the single `lib.rs`). Total Rust source: 43,009
lines across 29 files.

### Hub Crates (>10 consumers)

These are well-justified separations with many heterogeneous consumers.

| Crate | Consumers | Lines |
|---|---|---|
| tidefs-types-control-plane-core | 23 (13 non-types) | 2,135 |
| tidefs-types-vfs-core | 21 (18 non-types) | 8,118 |
| tidefs-types-incremental-job-core | 14 (14 non-types) | 1,861 |
| tidefs-types-extent-map-core | 11 (11 non-types) | 1,110 |
| tidefs-types-pool-label-core | 10 (10 non-types) | 866 |

**Recommendation**: Keep as-is. These are the foundation types layer.

### Stable Splits (3-8 consumers)

Snapshot of crates with 3-8 consumers as of 2026-05-18.  Two of the rows
below (`tidefs-types-policy-authority-core`, `tidefs-types-observe-core`)
were subsequently deleted and are historical archive entries only; the
remaining rows are the surviving stable splits.

| Crate | Consumers | Lines | Domain |
|---|---|---|---|
| tidefs-types-posix-filesystem-adapter-core | 8 | 1,188 | FUSE adapter types |
| tidefs-types-reclaim-queue-core | 7 | 1,489 | Space reclaim |
| tidefs-types-dataset-feature-flags-core | 6 | 689 | Dataset flags |
| tidefs-types-response-registry-core | 6 | 1,106 | Response registry |
| tidefs-types-dataset-lifecycle-core | 5 | 1,946 | Dataset lifecycle |
| tidefs-types-policy-authority-core | 5 | 1,352 | Historical archive entry; deleted 2026-06-01 |
| tidefs-types-publication-pipeline-core | 5 | 894 | Publication |
| tidefs-types-deferred-cleanup-core | 4 | 699 | Cleanup scheduling |
| tidefs-types-polymorphic-directory-index-core | 4 | 1,124 | Directory indexing |
| tidefs-types-cache-lattice-core | 3 | 1,421 | Cache topology |
| tidefs-types-claim-ledger-core | 3 | 999 | Claim ledger |
| tidefs-types-observe-core | 3 | 2,244 | Historical archive entry; deleted 2026-06-01 |
| tidefs-types-package-profile-catalog | 3 | 782 | Package profiles |
| tidefs-types-polymorphic-xattr-core | 3 | 924 | Extended attributes |
| tidefs-types-space-accounting-core | 3 | 1,975 | Space accounting |

**Recommendation (historical)**: Keep as-is for the surviving crates; each
represented a coherent domain boundary with multiple consumers that would not
have benefited from inlining.  The two deleted rows are archive evidence only.

### Near-Dead Splits (2 consumers)

| Crate | Consumers | Lines |
|---|---|---|
| tidefs-types-archive-control-core | 2 (schema-codec-outcome, xtask) | 986; deleted 2026-06-01 in the fresh checkout |
| tidefs-types-truth-view-core | 2 (schema-codec-outcome, xtask) | 1,352; deleted 2026-06-01 in the fresh checkout |
| tidefs-types-orphan-index-core | 2 (local-filesystem, orphan-index) | 1,303 |
| tidefs-types-transport-session | 2 (transport, replicated-object-store) | 2,870 |

### Dead Splits (single consumer)

| Crate | Sole Consumer | Lines |
|---|---|---|
| tidefs-types-continuity-charter | tidefs-posix-filesystem-adapter-daemon | 1,085 |
| tidefs-types-secret-key-policy-core | tidefs-secret-key-policy-runtime | 1,034 |
| tidefs-types-vfs-owned | tidefs-local-filesystem | 589 |

### Orphans (zero consumers, not in workspace)

| Crate | Lines | Status |
|---|---|---|
| tidefs-types-shadow-pilot | 2,125 | Historical archive entry; deleted 2026-06-01 |

## Dependency Graph

```
tidefs-types-control-plane-core  <── 10 types crates + 13 non-types crates
tidefs-types-vfs-core            <── 3 types crates + 18 non-types crates

types→types edges (all valid, no cycles):
  archive-control-core        → control-plane-core
  cache-lattice-core          → vfs-core
  claim-ledger-core           → control-plane-core, vfs-core
  deferred-cleanup-core       → dataset-feature-flags-core
  observe-core                → control-plane-core
  policy-authority-core       → control-plane-core
  posix-filesystem-adapter-core → control-plane-core
  publication-pipeline-core   → control-plane-core
  response-registry-core      → control-plane-core
  secret-key-policy-core      → control-plane-core
  truth-view-core             → control-plane-core, response-registry-core
  vfs-owned                   → vfs-core
```

No circular dependencies detected. No types crate depends on a non-types
`tidefs-*` crate. The dependency graph is a clean DAG with two root hubs
(`control-plane-core` and `vfs-core`).

## Consolidation Recommendations

### Priority 1: Remove orphan

**tidefs-types-shadow-pilot** was not a workspace member and had zero
consumers. It contained 2,125 lines of deterministic shadow-pilot model code
that was not referenced by any production or test code.

- 2026-06-01: directory `crates/tidefs-types-shadow-pilot/` deleted.
- No workspace member entry existed.

### Priority 2: Fold dead splits into sole consumers

Each dead split should be folded into its sole consumer as a private module.
The types are an implementation detail of the consumer crate, not a shared
contract.

| Dead Split | Fold Into | Lines |
|---|---|---|
| tidefs-types-continuity-charter | tidefs-posix-filesystem-adapter-daemon | 1,085 |
| tidefs-types-secret-key-policy-core | tidefs-secret-key-policy-runtime | 1,034 |
| tidefs-types-vfs-owned | tidefs-local-filesystem | 589 |

For each:
1. Copy the types source into the consumer crate as a module (e.g.,
   `src/continuity_charter.rs` or `src/types/continuity_charter.rs`).
2. Update the consumer's `Cargo.toml` to remove the dependency.
3. Update the consumer's imports: `use tidefs_types_continuity_charter::*`
   becomes `use crate::continuity_charter::*`.
4. Remove the dead crate directory and workspace member entry.
5. Remove the dead crate from any non-consumer `Cargo.toml` (e.g., xtask
   codegen lists).

### Priority 3: Near-dead splits (review candidates)

Historical note: **tidefs-types-archive-control-core** and
**tidefs-types-truth-view-core** used to share
the same two consumers: `tidefs-schema-codec-outcome` (runtime) and
`tidefs-xtask` (build-time codegen). These types describe schema structures
that only exist to support the codec. Recommendation: fold both into
`tidefs-schema-codec-outcome` as public modules; xtask can depend on
schema-codec-outcome at build time or reference the types through a shared
path.

2026-06-01 update: the fresh TideFS checkout no longer has
`tidefs-schema-codec-outcome`, and the surviving archive/truth-view record
surfaces live in `tidefs-types-vfs-core`; the excluded crate roots were
deleted instead of folded.

**tidefs-types-orphan-index-core** (2 consumers: `tidefs-local-filesystem`,
`tidefs-orphan-index`). These consumers share a tight domain relationship
(orphan index is an implementation detail of local-filesystem). Recommendation:
fold into `tidefs-orphan-index` as the authoritative crate; local-filesystem
already depends on orphan-index, so no new edge is needed.

**tidefs-types-transport-session** (2 consumers: `tidefs-transport`,
`tidefs-replicated-object-store`). These consumers are at different stack
layers; folding into either would create an undesirable dependency direction.
Recommendation: keep as-is until the transport/replication boundary matures.

### Deferred

**tidefs-types-policy-authority-core** was owned by #5939 in the historical
pre-rename workspace. 2026-06-01 update: the fresh TideFS checkout represents
the surviving policy-authority record surfaces in `tidefs-types-vfs-core`, and
the excluded crate root was deleted.

## Before / After

Historical consolidation projection as of 2026-05-18.  Several projected
removals were completed in the fresh checkout; see the per-row 2026-06-01
notes above for which rows are archive evidence rather than current counts.

| | Before | After (P1+P2) | After (P1+P2+P3) |
|---|---|---|---|
| types-core crates | 29 | 25 | 22 |
| dead splits (1 consumer) | 3 | 0 | 0 |
| orphans (0 consumers) | 1 | 0 | 0 |
| near-dead splits (2 consumers) | 4 | 4 | 1 |
| stable/hub crates | 21 | 21 | 21 |

After P1+P2+P3: 7 crates removed, 22 remain, 0 orphans, 0 dead splits.

## Dependency Graph (After Consolidation)

Historical projection as of 2026-05-18.  `tidefs-schema-codec-outcome` no
longer exists in the current checkout; the surviving archive/truth-view
record surfaces live in `tidefs-types-vfs-core`.

```
tidefs-types-control-plane-core  ── hub (10 types + 13 non-types consumers)
tidefs-types-vfs-core            ── hub (3 types + 18 non-types consumers)
tidefs-schema-codec-outcome      ── absorbs archive-control + truth-view types
tidefs-orphan-index              ── absorbs orphan-index-core types
tidefs-types-transport-session   ── unchanged (2 distinct consumers)
... remaining stable/hub crates unchanged
```

## Implementation Plan

**Historical note (2026-06-22)**: This plan was written against the
2026-05-18 workspace.  Several listed source and consumer crates have since
been deleted, and the consolidation strategy for issues 2-6 is superseded by
the fresh-checkout deletions recorded in the 2026-06-01 notes above.  The
numbered issue descriptions below are historical review input only; do not
execute them against the current checkout.

### Issue 1: Remove orphan tidefs-types-shadow-pilot
- Done 2026-06-01 in the fresh TideFS checkout.
- Deleted `crates/tidefs-types-shadow-pilot/`.
- Minimal risk, zero consumers.

### Issue 2: Fold tidefs-types-continuity-charter into posix-filesystem-adapter-daemon
- Move 1,085 lines as `apps/tidefs-posix-filesystem-adapter-daemon/src/continuity_charter.rs`
- Update imports and Cargo.toml
- Remove crate directory and workspace member

### Issue 3: Fold tidefs-types-secret-key-policy-core into secret-key-policy-runtime
- Move 1,034 lines as `crates/tidefs-secret-key-policy-runtime/src/types.rs`
- Update imports and Cargo.toml
- Remove crate directory and workspace member

### Issue 4: Fold tidefs-types-vfs-owned into local-filesystem
- Move 589 lines as `crates/tidefs-local-filesystem/src/vfs_owned.rs`
- Update imports and Cargo.toml
- Remove crate directory and workspace member

### Issue 5: Fold archive-control-core + truth-view-core into schema-codec-outcome
- Move 2,338 combined lines into `crates/tidefs-schema-codec-outcome/src/types/`
- Update xtask codegen references
- Remove both crate directories and workspace members

### Issue 6: Fold orphan-index-core into orphan-index
- Move 1,303 lines into `crates/tidefs-orphan-index/src/types.rs`
- Update local-filesystem imports
- Remove crate directory and workspace member


- `cargo check --workspace` passes before and after each merge.
  inventory tables above).
- Cross-referenced with #5939: policy-authority-core deferred, no overlap.
- No layering violations found: types crates depend only on other types crates
  plus external crates (serde, core, alloc).
