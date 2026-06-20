# Receive merge-planner design: dataset merge model and conflict taxonomy

**Status**: Decision record
**Issue**: [#704](https://github.com/tidefs/tidefs/issues/704)
**Design authority**: `docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3
**Date**: 2026-06-21
**TFR link**: TFR-010

## Purpose

`docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3 records the fail-closed policy for
conflicting non-empty receive targets: TideFS refuses the receive with a
classified error and requires the operator to resolve the conflict through
explicit actions (delete-and-rereceive, create missing base snapshot, or
rollback to a shared ancestor).  §1.3 rationale names the general dataset
merge problem that must be solved before automatic conflict resolution can
be offered.

This document defines that merge model: a conflict taxonomy for diverged
pool states, an operator-policy surface, a timing decision for merge relative
to receive transport, an authority assignment per conflict class, and a
follow-up implementation issue map.  It is the design artifact for issue #704.

**This is a design record only.**  It does not edit send/receive runtime
source, changed-record encoding, transaction-manifest structure, or the
current fail-closed receive path.

## Evidence Reviewed

- `docs/RECEIVE_STREAM_MERGE_POLICY.md` §1.3 — current fail-closed policy and
  rationale.
- `docs/SEND_RECEIVE_OW109.md` — still-open items: incremental resume,
  non-empty target conflict resolution, and multi-writer conflict resolution.
- `docs/LOCAL_SNAPSHOTS_OW108.md` — still-open items: non-empty target merge,
  unified deadlists, placement receipts, snapshot-reclaim accounting.
- `docs/REVIEW_TODO_REGISTER.md` TFR-010 — snapshot/clone/send-receive/deadlist
  coherence gap.
- ZFS `zfs receive -F` semantics — force-rollback, discard local changes since
  last common snapshot; no general merge.
- btrfs send/receive semantics — per-subvolume incremental apply with
  parent UUID anchoring; refuses non-empty divergent targets; no general
  merge.
- `crates/tidefs-local-filesystem/src/send_receive.rs` — current receive
  implementation: staging, checkpoint, base-root protection, omitted-content
  validation, snapshot-root rewriting.
- `crates/tidefs-local-filesystem/src/encoding.rs` — changed-record stream
  versions, root-summary digests, transaction-manifest checksums.

## Non-Goals

- Do not edit send/receive runtime source or changed-record encoding in this
  design slice.
- Do not implement the merge planner; implementation belongs to follow-up
  issues.
- Do not change the current fail-closed policy for non-empty targets; the
  merge planner is a future enhancement, not a reversion of the fail-closed
  gate.
- Do not define distributed multi-pool merge semantics; this design is scoped
  to local single-pool receive with a diverged target.
- Do not close TFR-010.  This design narrows the snapshot/send-receive
  coherence gap for merge but does not unify deadlists, placement receipts,
  or distributed reclaim.
- Do not replace the receive checkpoint and resume model defined by
  `docs/RECEIVE_STREAM_MERGE_POLICY.md` §2.

## 1. Conflict taxonomy

When two pools have diverged from a common ancestor, the objects in each pool
can differ along five independent axes.  Each axis is a conflict class with
its own classification rules and resolution authority.

### 1.1 Inode identity conflicts

A conflict exists when the same inode number (`inode_id`) appears in both the
stream's committed-root namespace and the target's current committed-root
namespace, but the inode records differ in any non-timestamp field.

Divergence can produce:

| Divergence kind | Detection evidence | Example |
|---|---|---|
| Different file type | `InodeRecord::file_type` mismatch | Side A created a regular file at inode 100; side B created a directory at inode 100 |
| Different content identity | Different `content_manifest_id`, different extent layout, or different checksum root | Same file edited on both sides |
| Different permissions/ownership | `InodeRecord` permission, uid, gid, or ACL fields differ | `chmod` on one side, `chown` on the other |
| Different size | `InodeRecord::size` differs with same content identity | Sparse file extended on one side only |

**Authority**: The inode namespace is owned by the dataset's committed-root
chain.  The merge planner must compare the stream's root-summary inode table
against the target's current root-summary inode table.  Common-ancestor
inode-table state provides the baseline for divergence classification.

**Resolution domain**: per-inode, independent of directory entry and extent
map conflicts.  An inode-only conflict (same file, same extents, different
permissions) can be resolved without touching extent maps.

### 1.2 Directory entry conflicts

A conflict exists when the same directory inode has a different set of named
children on each side.

| Divergence kind | Detection evidence | Example |
|---|---|---|
| Child added on one side only | Entry present in one namespace, absent in the other | `touch /a/new` on side A only |
| Child deleted on one side only | Entry absent in one namespace, present in the other | `rm /a/old` on side A only |
| Same name, different inode | Same entry name maps to different `inode_id` on each side | `mv` replaced a file on side A, side B still has the old inode |
| Same name, same inode, but inode diverged | Both sides agree on the entry→inode mapping but the inode itself diverged (§1.1) | File edited on both sides, name unchanged |
| Directory entry reordering | Same entries, different order | `readdir` order differs; usually not a correctness conflict |

**Authority**: The directory entry namespace is owned by the dataset's
committed-root chain and is traversed through the inode table.  The merge
planner must compare directory manifests (or inode-to-children maps) from
the common ancestor, the stream root, and the target root.

**Resolution domain**: per-directory, per-entry.  An add-only divergence (no
deletions or replacements) is conflict-free and can be auto-merged.  A
delete on one side and a modify on the other is a true conflict requiring
operator policy.

### 1.3 Extent map conflicts

A conflict exists when the same inode has a different extent map on each side:
different block allocations, different extent boundaries, or different content
chunk references.

| Divergence kind | Detection evidence | Example |
|---|---|---|
| Content chunk replaced | Same logical offset, different content chunk identity | Byte-range edit on both sides |
| Extent boundaries differ | Different `Extent` shape (offset, length, content ref) | Reflink clone on one side changed extent sharing |
| Hole vs data | One side has a hole at an offset, the other has data | Truncate on one side, write on the other |
| Allocation-only difference | Same content, different physical block locations | Rebalance, compaction, or dedup on one side changed block placement without changing content |

**Authority**: The extent map is owned by the inode's content manifest chain.
The merge planner must compare extent maps keyed by `inode_id` and logical
offset range across the common ancestor, stream, and target roots.  Content
identity is the authoritative comparison key, not physical block location.

**Resolution domain**: per-inode, per-byte-range.  Non-overlapping byte-range
edits on the same file can be auto-merged (both sides wrote to different
regions).  Overlapping byte-range edits are a true conflict requiring operator
policy.

### 1.4 Snapshot catalog conflicts

A conflict exists when the stream's snapshot catalog and the target's snapshot
catalog diverge in name, root identity, clone lineage, or hold/protection
state.

| Divergence kind | Detection evidence | Example |
|---|---|---|
| Same name, different root | Same snapshot name maps to different committed-root digests | Same snapshot name reused on both sides for different roots |
| Different name sets | Side A has snapshots side B does not, or vice versa | Independent snapshot creation after divergence |
| Clone lineage divergence | Clone origin or promotion state differs | Clone promoted on one side but not the other |
| Hold/pin divergence | Different hold sets or lifecycle pin state for the same snapshot | Hold added on one side only |
| Catalog entry lifespan | Side A deleted a snapshot, side B still has it | Pruning on one side only |

**Authority**: The snapshot catalog is owned by the superblock-authenticated
catalog and lifecycle-pin authority.  The merge planner must compare catalog
entries keyed by snapshot name, root identity, clone flags, and hold/pin state.

**Resolution domain**: per-catalog-entry.  Name collisions with different
root identities are the hardest conflict here; different name sets without
collisions are conflict-free (both sides' snapshots can coexist).

### 1.5 Generation ordering conflicts

A conflict exists when the stream and target have advanced their respective
transaction-group (txg) or generation counters independently, and the merge
planner cannot determine a total ordering for a specific object without
operator input.

| Divergence kind | Detection evidence | Example |
|---|---|---|
| Independent txg advance | Stream's current txg > common ancestor txg, target's current txg > common ancestor txg, no shared post-ancestor txg | Both pools accepted writes after divergence |
| Same txg, different content | A txg exists on both sides but commits different objects | Not possible under the single-writer model unless a fork occurred; evidence of a data corruption or pool split |
| Missing txg stride | The stream's txg sequence has gaps relative to the target's sequence, or vice versa | One pool was rolled back and replayed a different sequence |

**Authority**: The transaction-group sequence is owned by the pool's
commit-ordering authority.  The merge planner must use the common ancestor's
last txg as the divergence point.  Every object on each side carries its
birth txg and, for deletions, its death txg.

**Automatic resolution**: The merge planner can auto-resolve ordering when
one of these conditions holds:

- An object exists on only one side (birth txg > common ancestor txg on that
  side, no corresponding object on the other side).  Keep it.
- An object was deleted on one side (death txg recorded) but untouched on the
  other.  If the policy is `merge-latest`, honour the deletion.
- An object exists on both sides with identical content identity (same
  checksum root, same extent layout, same inode record).  No conflict —
  either side's copy is correct.

**True ordering conflicts**: An object was modified on both sides (different
content identity, different birth txgs on each side, both > common ancestor
txg).  The merge planner cannot choose a winner without operator policy.

## 2. Operator-policy surface

The merge planner exposes four policy axes that the operator sets before
a merge-capable receive.  Policies can be set per-conflict-class or as a
single default.

### 2.1 Policy definitions

| Policy | Behaviour | Use case |
|---|---|---|
| `keep-local` | For conflicting objects, retain the target's version and discard the stream's version. | Target is the primary writer; the stream is a stale or partial replica. |
| `keep-remote` | For conflicting objects, accept the stream's version and discard the target's version. | Stream is the primary writer; the target is a stale replica being resynchronised. |
| `merge-latest` | For conflicting objects, compare birth txgs and keep the object with the higher txg. If txgs are equal, the policy falls through to `keep-local` (target-wins tiebreak). | Both sides have been written independently; the operator trusts txg ordering as a proxy for "newer". |
| `manual` | Do not auto-resolve any conflict. Report the full conflict inventory and require the operator to resolve each object or object class before the receive may proceed. | Sensitive datasets, regulatory environments, or when the operator needs to audit every divergence. |

### 2.2 Policy granularity

The policy can be set at three levels:

1. **Global default**: one policy for all conflict classes.  The simplest
   surface: `tidefsctl receive --merge-policy keep-local`.

2. **Per-class override**: the operator can override the global policy for a
   specific conflict class.  Example: `keep-local` for everything, but
   `keep-remote` for snapshot catalog entries (accept the stream's snapshots).

3. **Per-object resolution** (planned, not V1): for `manual` policy, the
   operator inspects the conflict inventory and provides per-object
   instructions.  This requires a conflict-inventory save/load format and a
   `tidefsctl merge resolve` subcommand.

### 2.3 Conflict-free auto-merge

Regardless of the operator policy, objects that are conflict-free by the
taxonomy in §1 are always auto-merged.  The operator policy only governs
conflicting objects.  Conflict-free means:

- Object exists on only one side (no same-identity counterpart on the other).
- Object exists on both sides with identical content identity.
- Non-overlapping byte-range modifications to the same inode.
- Non-colliding snapshot catalog entries.

This ensures that `keep-local` and `keep-remote` do not silently discard
independent, non-conflicting work done on the losing side.

## 3. Merge timing: pre-receive planning

### 3.1 Decision: pre-receive plan, in-receive execute

The merge planner operates as a **pre-receive planning step** that produces a
merge plan consumed by the receive path during **in-receive execution**.

**Pre-receive planning** loads the stream's lineage manifest and the target's
current committed-root state, locates the common ancestor (if one exists),
produces a conflict inventory, applies the operator policy, and emits a
binding merge plan.  The plan is a machine-readable sequence of per-object
decisions: keep-local, keep-remote, or specific resolution instructions.

**In-receive execution** consumes the merge plan alongside the stream.  When
the receive path encounters an object that exists in both the stream and the
target, it consults the plan rather than failing closed.  The plan may
instruct:

- Skip this object (keep-local, target already has it).
- Overwrite this object with the stream's version (keep-remote).
- Commit both versions under a conflict-marker namespace (manual, unresolved).

The receive path remains the authority for object import, re-signing with
the destination root-authentication key, snapshot-root rewriting, and
omitted-content validation.

### 3.2 Why pre-receive, not post-receive

Post-receive reconciliation (receive everything into a staging pool, then
merge) is rejected for the following reasons:

1. **Storage cost**: a diverged pool may have terabytes of data.  Receiving
   the entire stream into a staging area doubles capacity pressure before
   reconciliation.
2. **Identity fragmentation**: receiving conflicting objects into a staging
   area creates two copies of every conflicting inode, directory, and extent
   map.  The reconciliation step must then choose one and discard the other,
   leaving orphaned objects that the deadlist/reclaim path must clean up.
3. **Snapshot catalog coherence**: snapshot roots must be imported before the
   current root.  If the staging pool and the target pool have conflicting
   snapshot catalogs, post-receive reconciliation must untangle two catalogs
   that were never designed to coexist in one pool.
4. **Failure blast radius**: if reconciliation fails midway, the staging
   pool is in an undefined state that may be unrecoverable without deleting
   both the staging and target pools.

Pre-receive planning avoids all four problems: the merge plan is produced
from metadata-only inspection (root summaries, inode tables, directory
manifests, extent maps, snapshot catalogs) without importing any content
chunks.  Content chunk import happens during receive, guided by the plan.

### 3.3 No-common-ancestor case

If the stream and target share no common ancestor (no root in the target's
recovery audit matches any root identity in the stream's lineage manifest),
the merge planner cannot produce a conflict inventory.  The receive is not a
merge — it is a fresh pool import into a non-empty target.  The merge planner
must refuse with a `no_common_ancestor` error and direct the operator to the
existing delete-and-rereceive or fresh-target paths documented in
`RECEIVE_STREAM_MERGE_POLICY.md` §1.3.

## 4. Authority model per conflict class

Each conflict class has a designated authority that owns the classification
and resolution decision for that class.

### 4.1 Authority assignment

| Conflict class | Classification authority | Evidence needed | Resolution authority |
|---|---|---|---|
| Inode identity | Merge planner | Stream root-summary inode table, target root-summary inode table, common-ancestor inode table | Operator policy + merge planner (merge-latest uses txg comparison) |
| Directory entry | Merge planner | Stream directory manifest, target directory manifest, common-ancestor manifest | Operator policy + merge planner (add-only is auto-merge regardless of policy) |
| Extent map | Merge planner | Stream inode content manifest, target inode content manifest, common-ancestor manifest, content chunk checksums | Operator policy (non-overlapping byte ranges auto-merge regardless of policy) |
| Snapshot catalog | Merge planner + snapshot lifecycle authority | Stream catalog, target catalog, lifecycle-pin state | Operator policy (non-colliding names auto-merge regardless of policy) |
| Generation ordering | Merge planner | Birth txg, death txg, common-ancestor txg, stream current txg, target current txg | Operator policy + merge planner (txg ordering for merge-latest) |

### 4.2 Merge planner authority boundaries

The merge planner owns the conflict inventory, the merge plan, and the
planning phase.  It does **not** own:

- **Receive transport and stream decoding** — owned by the changed-record
  receive path (`send_receive.rs`).
- **Changed-record encoding** — owned by the stream format version authority
  (`encoding.rs`).
- **Root authentication and re-signing** — owned by the root-authentication
  key and committed-root authority.
- **Snapshot lifecycle and catalog pinning** — owned by the snapshot
  lifecycle authority (`LOCAL_SNAPSHOTS_OW108.md`).
- **Deadlist and reclaim accounting** — owned by the deadlist/reclaim
  authority (TFR-010 open item).
- **Placement receipts and placement-gated receive** — owned by the placement
  receipt authority (#18, #674, #675).

The merge planner **consumes** evidence from these authorities as inputs but
does not change their behaviour, data formats, or invariants.

### 4.3 Operator as ultimate authority

When the policy is `manual`, the operator is the resolution authority.  The
merge planner produces the conflict inventory and stops.  The operator must
provide per-object or per-class resolution instructions before the receive may
proceed.

## 5. Implementation sequencing

The merge planner is a future enhancement; the current fail-closed policy
remains authoritative until the merge planner is implemented and validated.

### 5.1 Follow-up implementation issues

The design splits into focused issues with non-overlapping expected write sets:

1. **`receive-merge-planner-common-ancestor`** — implement the common-ancestor
   location algorithm.  Given a stream lineage manifest and a target recovery
   audit, find the highest txg present in both.  Expected write set:
   `crates/tidefs-local-filesystem/src/receive_merge_planner.rs` (new),
   `crates/tidefs-local-filesystem/src/send_receive.rs` (common-ancestor
   call-site only), tests.  Does not touch the fail-closed gate.

2. **`receive-merge-planner-conflict-inventory`** — implement the conflict
   inventory builder.  Compare stream and target root summaries, inode tables,
   directory manifests, extent maps, and snapshot catalogs against the common
   ancestor.  Produce a machine-readable conflict inventory.  Expected write
   set: `receive_merge_planner.rs`, `src/encoding.rs` (conflict-inventory
   types), tests.  Does not edit the receive path.

3. **`receive-merge-planner-operator-policy`** — implement the operator-policy
   surface.  Expose `--merge-policy` on the receive path and `tidefsctl
   receive`; implement the policy resolution engine that consumes a conflict
   inventory and an operator policy and produces a merge plan.  Expected write
   set: `receive_merge_planner.rs`, `src/cli.rs` or operator-flag parsing,
   `src/lib.rs` (receive entry-point dispatch), tests.

4. **`receive-merge-planner-in-receive-execution`** — integrate the merge plan
   into the receive execution path.  When a merge plan is present, the receive
   path consults it for conflicting objects instead of failing closed.  This
   is the step that relaxes the §1.3 fail-closed gate.  Expected write set:
   `send_receive.rs`, `receive_persistence.rs` (merge-plan integration point),
   tests.  Must land after the plan-building issues above.

5. **`receive-merge-planner-cli-resolve`** — implement the `manual`
   resolution surface.  Save/load conflict inventories, expose `tidefsctl
   merge resolve` for per-object resolution, and validate resolved inventories
   before admitting the receive.  Expected write set: `receive_merge_planner.rs`,
   `tidefsctl` subcommand, tests.  Can land independently of the in-receive
   execution issue.

Each issue must state its prerequisite issues (if any) in its body and keep
its write set disjoint from the others so they can be developed in parallel
except where explicit data-flow dependencies exist (issue 4 depends on issues
1–3).

### 5.2 What this design does not close

- TFR-010 remains open until the merge planner, unified deadlists, placement
  receipts, and distributed snapshot reclaim are implemented and validated.
- The current fail-closed policy in `RECEIVE_STREAM_MERGE_POLICY.md` §1.3
  remains authoritative until issue 4 (`receive-merge-planner-in-receive-execution`)
  is merged.
- This design does not add distributed merge semantics.  Cross-pool merge
  requires multi-pool identity, membership fencing, and epoch-bound stream
  comparison that are not yet designed.
- This design does not relax the receive checkpoint model or the omitted-content
  validation requirements.

## 6. Validation tier

Documentation/design validation:

- `git diff --check` on this file.
- Source inspection to confirm no edited send/receive runtime source or
  changed-record encoding.
- Issue body cross-reference: each follow-up issue names this document as its
  design authority.
- `RECEIVE_STREAM_MERGE_POLICY.md` §1.3 cross-reference: this document is the
  design slot delegated by that section.

Focused Rust send/receive checks and merge-planner implementation tests belong
to the follow-up implementation issues.
