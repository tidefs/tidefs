# Dataset Lifecycle State Machine Design (Historical Input)

Maturity: **historical input** - imported dataset-lifecycle target design, not
current TideFS implementation status, product behavior proof, or claim-registry
authority.

Authority classification: TFR-019 / `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
leaves this document as historical input. Use live source, current authority
docs, and `validation/claims.toml` for current dataset-lifecycle status.

Historical note: this imported document recorded a Forgejo issue #1219
closeout. It does not close any current GitHub dataset-lifecycle,
destroy-worker, cluster-consensus, release-readiness, or production-readiness
item.

## 1. Motivation

Datasets in a production storage system are long-lived objects that must be created,
operated, and eventually destroyed. Without an explicit lifecycle state machine,
dataset destruction is unsafe on multiple axes:

- **Mount safety**: Nothing prevents a destroyed dataset from being mounted by a
  stale client or a late-arriving mount request, leading to data interpretation
  errors or silent corruption.
- **In-flight mutation fencing**: If a writer holds a lease while a destroy is
  requested, the system must either wait for the lease to drain or forcibly
  revoke it — without a state machine, there is no mechanism to track this
  transition.
- **GC coordination**: The garbage collector must not reclaim metadata blocks
  that a running destroy job still needs to traverse. Pinned traversal roots
  solve this, but they require the state machine to define the transition point.
- **Cluster consistency**: In a multi-node deployment, all peers must agree that
  a dataset no longer exists. The state machine provides the authoritative
  anchor for this consensus.

ZFS and Ceph are prior-art inputs for the destroy lifecycle problem, not
evidence for a current TideFS product claim. ZFS handles destroy as an
immediate operation: `zfs destroy` removes the dataset and all snapshots inline,
blocking writer access through the DMU's commit_group commit ordering. Ceph's
approach (RADOS pool deletion with `mon_allow_pool_delete`) relies on monitor
configuration flags.

tidefs takes a different design direction: destroy is a first-class state
transition with explicit fencing, GC-safe traversal roots, and a tombstone phase
for cluster consensus. This is a design target for safer concurrency and
observability; validated successor, performance, availability, or operational
cost claims remain blocked behind #875 and #928/#930 comparator evidence.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1223 (dataset feature flags) | Mount-time gating | Feature flags check runs first; state check runs second. ACTIVE + feature_ok = mount allowed. DESTROYING/TOMBSTONE = mount refused regardless of features. |
| #1254 (pool import/export) | Pool-level state | `PoolState::ACTIVE` is a prerequisite for opening any dataset. Dataset state is nested under pool state. A pool in `EXPORTED`/`DESTROYED` state means all datasets are inaccessible. |
| #1213 (VFS Engine API) | Inode lifetime invariant | The VFS contract's inode lifetime invariant (inode exists until last close) must be honored: DESTROYING state must fence new opens while allowing existing file descriptors to drain. |
| #1207 (orphan index) | Orphan reaping | Tombstone reaper must process orphans before releasing blocks. Dataset destroy finalizes orphan cleanup through the orphan index's reclaim path. |
| #1267 (COMMIT_GROUP state machine) | Commit ordering | Destroy transition is a transactional event: the state change, poison signal, and pinned roots record must commit atomically within a single commit_group. |
| #1283 (cluster membership) | Cluster-wide consensus | DESTROYING state change must propagate to all cluster peers before the TOBSTONE transition. Peers must refuse mount for non-ACTIVE datasets. |

## 3. DatasetStateV1 Enum and Transition Rules

### 3.1 State enum

```
DatasetStateV1: u8 {
    Active     = 0x01,  // Normal operation; mountable; writes allowed
    Destroying = 0x02,  // Destroy in progress; NOT mountable; writes fenced
}
```

Values 0x00 and 0x04-0xFF are reserved for future states. Any unrecognized
state on disk must be treated as equivalent to `Tombstone` (refuse mount,
preserve for observability). This is a conservative default: it's safer to
refuse mount than to risk data corruption from an unknown state.

### 3.2 State transition diagram

```
                    create
    (none) ──────────────────► ACTIVE
                                  │
                                  │ tidefsctl dataset destroy
                                  │ (or admin-plane destroy RPC)
                                  ▼
                            DESTROYING ─────► (error/abort) ──► ACTIVE
                                  │                                 ▲
                                  │ destroy job completes           │
                                  │ (all blocks reclaimed,          │
                                  │  orphans processed)             │
                                  ▼                                 │
                            TOMBSTONE ──────────────────────────────┘
                                  │                    (undo-tombstone
                                  │                     admin recovery)
                                  │
                                  │ tombstone_reaper
                                  │ (background, after
                                  │  cluster consensus)
                                  ▼
                              (deleted)
```

### 3.3 Transition rules

**ACTIVE → DESTROYING** (trigger: `tidefsctl dataset destroy <name>` or admin-plane RPC)

Pre-conditions:
- Dataset must be in ACTIVE state.
- No clone children exist whose origin points to this dataset (V1: return `EBUSY`;
  future: promote clones per dataset property policy).
- Caller must hold admin capability (authenticated admin-plane request).

Atomic commit (single commit_group):
1. Write `DatasetStateV1::Destroying` to the dataset record's state field.
2. Write `DestroyJobRecordV1` to the dataset's system area:
   - `destroy_job_id: u64` — unique job identifier
   - `destroy_commit_group: u64` — commit_group at which destroy was initiated
   - `destroy_flags: u32` — bitmask (see §3.4)
   - `pinned_roots: [TraversalRoot; N]` — GC-pinned traversal roots (§6)
4. Poison all active mounts for this dataset (§5).

Post-commit:
- Destroy worker begins asynchronous reclamation:
  - Walk all objects in the dataset (inodes, extents, xattrs, directory entries).
  - Release space through the allocator for each reclaimed block.
  - Process orphan inodes through the orphan index (#1207).
  - When reclamation completes: transition to TOMBSTONE.

**DESTROYING → ACTIVE** (trigger: destroy abort — admin intervention)

Pre-conditions:
- Destroy job must not have completed (i.e., not yet in TOMBSTONE).
- Caller must hold admin capability.

Atomic commit:
1. Write `DatasetStateV1::Active` back to the dataset record.
2. Delete the `DestroyJobRecordV1`.
3. Unpin all traversal roots — release from GC root set.
4. Un-poison active mounts (restore normal operation).

Note: Partial reclamation is NOT rolled back. Blocks already freed during the
aborted destroy remain freed. This is intentional — re-running destroy later
will pick up where it left off.

**DESTROYING → TOMBSTONE** (trigger: destroy worker completes all reclamation)

Pre-conditions:
- Destroy worker has verified all objects are reclaimed.
- All orphan inodes processed and freed.
- Space accounting updated (logical and physical space zeroed for dataset).

Atomic commit:
1. Write `DatasetStateV1::Tombstone` to the dataset record.
2. Update `DestroyJobRecordV1` with completion metadata:
   - `bytes_reclaimed: u64`
   - `objects_reclaimed: u64`
   - `completion_commit_group: u64`

**TOMBSTONE → ACTIVE** (trigger: admin recovery — "undo destroy")

Pre-conditions:
- Tombstone record must still exist (not yet reaped by tombstone reaper).
- Caller must hold admin capability.
- This is a disaster-recovery path, not a normal operation.

Atomic commit:
1. Write `DatasetStateV1::Active` to the dataset record.
2. Clear the `DestroyJobRecordV1` completion fields (or delete record).
3. Dataset is mountable again. Data that was already reclaimed is NOT recovered
   — this only recovers the dataset namespace; reclaimed blocks are permanently
   lost. The admin is responsible for understanding this consequence.

**TOMBSTONE → (deleted)** (trigger: tombstone reaper — §7)

No dataset record remains. The tombstone reaper removes the dataset entry from
the pool's dataset catalog and releases the dataset record's own metadata blocks.

### 3.4 Destroy flags

```
DestroyFlags: u32 bitmask {
    FORCE_UNMOUNT    = 0x01,  // Force-unmount active FUSE sessions immediately
    SKIP_ORPHANS     = 0x02,  // Skip orphan index processing (emergency destroy)
    NO_TOMBSTONE     = 0x04,  // Skip TOMBSTONE phase; delete immediately after reclamation
}
```

## 4. Mount-Time State Check Algorithm

The mount path for a dataset involves two sequential checks: feature flags
(#1223) followed by lifecycle state (this design).

### 4.1 Algorithm

```
DatasetOpenGate::check(
    engine_supported: &HashSet<FeatureName>,
    dataset: &DatasetRecord,
) -> Result<DatasetOpenResult> {
    // Step 1: Feature flag check (per #1223)
    let feature_result = FeatureGate::check_dataset_features(
        engine_supported,
        &dataset.feature_flags,
    )?;

    // Step 2: Lifecycle state check
    match dataset.state {
        DatasetStateV1::Active => {
            // Mount allowed; apply feature-gate RO constraint if applicable
            match feature_result {
                FeatureGateResult::ReadWrite => Ok(OpenResult::ReadWrite),
                FeatureGateResult::ReadOnlyRequired { .. } => Ok(OpenResult::ReadOnly),
            }
        }
        DatasetStateV1::Destroying => {
            Err(OpenError::DatasetNotFound {
                dataset_name: dataset.name.clone(),
                reason: "dataset is being destroyed",
            })
        }
        DatasetStateV1::Tombstone => {
            Err(OpenError::DatasetNotFound {
                dataset_name: dataset.name.clone(),
                reason: "dataset has been destroyed",
            })
        }
        _ => {
            // Unknown state: conservative refusal (see §3.1)
            Err(OpenError::DatasetNotFound {
                dataset_name: dataset.name.clone(),
                reason: "dataset in unrecognized lifecycle state",
            })
        }
    }
}
```

### 4.2 Error semantics

Both DESTROYING and TOMBSTONE return the same error: `DatasetNotFound`. This is
intentional — from the client's perspective, a destroying/tombstone dataset no
longer exists. Distinguishing between "being destroyed" and "already destroyed"
is an admin-plane concern, not a client-facing one.

The error MUST be `ENOENT` at the VFS layer, consistent with the semantics of
an unlinked file: the name no longer resolves. This differs from ZFS which
returns a generic I/O error for destroyed datasets; tidefs uses `ENOENT` to
enable clean error handling in applications that retry on I/O errors but not on
existence errors.

### 4.3 Integration with pool import

The pool import path (#1254) checks `PoolState` first:

1. `PoolState::ACTIVE` → proceed to dataset open (feature check + state check).
2. `PoolState::EXPORTED` → pool-level mount refused; no dataset opens possible.
3. `PoolState::DESTROYED` → pool-level mount refused.

Dataset lifecycle state is only meaningful within a pool that is ACTIVE.

## 5. Poison Semantics for Active Mounts During Destroy

When a dataset transitions ACTIVE → DESTROYING, any existing FUSE mounts or
internal file handles must be fenced. This is the "poison" mechanism.

### 5.1 Poison state machine

```
MOUNT_OK ──► POISON_PENDING ──► POISON_ACTIVE ──► MOUNT_DEAD
                 │                    │
                 │ (drain complete)   │ (timeout)
                 ▼                    ▼
              MOUNT_OK            MOUNT_DEAD
           (abort path)
```

**POISON_PENDING:** The dataset has entered DESTROYING. The mount is notified.
New operations (read/write/open/create) are rejected with `EIO`. Existing
in-flight operations are allowed to complete within a grace period. The FUSE
daemon should begin draining its session.

**POISON_ACTIVE:** The grace period expired or `FORCE_UNMOUNT` was set. All
outstanding operations are cancelled. The FUSE session is torn down with
`FUSE_DESTROY`. New client connections receive `ENOENT`.

**MOUNT_DEAD:** The FUSE session is fully terminated. The mount point is
released. This is a terminal state for the mount handle.

### 5.2 Grace period

Default: 30 seconds. Configurable via dataset property `destroy_grace_secs`.
Rationale: most in-flight FUSE operations complete within milliseconds, but
long-running operations (e.g., large writes over slow networks) may need longer.
30 seconds is a compromise that avoids indefinite blocking while accommodating
reasonable workloads.

If `FORCE_UNMOUNT` is set in the destroy flags, the grace period is zero.

### 5.3 FUSE daemon integration

The FUSE daemon (`tidefs-posix-filesystem-adapter-daemon`) must:

   feed or local notification channel).
2. On receiving DESTROYING notification for a mounted dataset:
   - Enter POISON_PENDING.
   - Stop dispatching new FUSE requests for that dataset.
   - Drain the request queue (complete or cancel in-flight operations).
   - If drain completes within grace period: signal ready for MOUNT_DEAD.
   - If grace period expires or FORCE_UNMOUNT: force-cancel, enter MOUNT_DEAD.
3. Emit `FUSE_DESTROY` to the kernel to tear down the FUSE session.

### 5.4 Writer lease interaction

If cluster writer leases (#1248) are held for the dataset being destroyed:

1. The DESTROYING transition must recall (revoke) all writer leases.
2. Lease holders must flush dirty data and acknowledge recall before the
   grace period expires.
3. If a lease holder fails to acknowledge within the grace period, the lease
   is forcibly revoked and the holder's writes may be lost (the destroy
   continues regardless — safety trumps data preservation for a dataset being
   intentionally destroyed).

## 6. Pinned Traversal Root Mechanism

### 6.1 Problem

A destroy job cannot atomically scan and reclaim all dataset objects. The GC
might run concurrently and reclaim blocks that the destroy job still needs to
traverse (e.g., an inode table block that the destroy job hasn't yet visited
but plans to visit for reclamation accounting).

ZFS solves this with the "spacemap" approach: the destroy iterates the block
tree incrementally while the spacemap tracks freed blocks. But this couples
destroy to the allocator, creating contention on the spacemap lock.

tidefs separates traversal from reclamation: the destroy job records "pinned
roots" that act as GC barriers, then iterates at its own pace.

### 6.2 TraversalRoot record

```
TraversalRoot {
    root_type: TraversalRootType,
    block_pointer: BlockPointer,  // Root block of the structure
    estimated_objects: u64,       // Approximate count for progress reporting
}

TraversalRootType: u8 {
    InodeTable  = 0x01,  // Root of the dataset's inode B-tree
    ExtentMap   = 0x02,  // Root of the extent map catalog
    DirectoryIndex = 0x03,  // Root of the directory index
    XattrStore  = 0x04,  // Root of the xattr storage
    SnapshotCatalog = 0x05,  // Root of the snapshot catalog
    FeatureFlags = 0x06,  // Feature flag B-trees (reclaimed last)
}
```

### 6.3 Pinning protocol

1. On ACTIVE → DESTROYING, the destroy job identifies all traversal roots from
   the dataset record (inode table root, extent map catalog root, etc.).
2. These roots are written to `DestroyJobRecordV1.pinned_roots`.
3. The GC treats `pinned_roots` as additional GC roots: any block reachable
   from a pinned root is NOT eligible for reclamation, even if no "live"
   reference exists.
4. As the destroy job processes each root:
   - It traverses the structure, reclaiming all leaf blocks.
   - When a root is fully processed, it is removed from `pinned_roots`.
   - Progress is updated in `DestroyJobRecordV1` (objects_reclaimed counter).
5. When all roots are processed, `pinned_roots` becomes empty, and the destroy
   job transitions to TOMBSTONE.

### 6.4 Crash safety

If the system crashes during destroy:

- On recovery, the dataset is still in DESTROYING state.
- `DestroyJobRecordV1.pinned_roots` are re-pinned on recovery.
- The destroy worker resumes from the root that was in progress (partial root
  traversal is safe: the GC preserved all reachable blocks).
- No blocks are double-freed: the allocator tracks freed blocks per commit_group, and
  the destroy worker only frees blocks that haven't been freed already.

## 7. Tombstone Reaper Policy

### 7.1 Purpose

TOMBSTONE datasets persist briefly for:
- Cluster consensus: all peers must acknowledge the destroy before the dataset
  record is physically removed.
- Admin observability: `tidefsctl dataset list` shows TOMBSTONE datasets with
  `bytes_reclaimed` and destroy completion time.
- Late error handling: clients that attempt to open a destroyed dataset get a
  stable `ENOENT` rather than a transient "not found" that might be retried.

### 7.2 Reaper algorithm

The tombstone reaper is a background task that runs periodically (default: every
60 seconds, configurable via `tombstone_reaper_interval_secs` pool property).

```
tombstone_reaper(pool):
    for each dataset in pool.dataset_catalog where state == Tombstone:
        if dataset.destroy_job.completion_commit_group + tombstone_min_age_commit_groups < current_commit_group:
            if cluster_consensus_reached(dataset):
                reap_dataset_record(dataset)
```

### 7.3 Minimum tombstone age

Default: 100 commit_groups (~100 seconds at 1 commit_group/sec). Configurable via pool property
`tombstone_min_age_commit_groups`. Rationale: cluster consensus propagation typically
completes within 10-20 commit_groups; 100 commit_groups provides a generous safety margin for
network partitions and slow peers.

### 7.4 Cluster consensus requirement

Before reaping, the tombstone reaper must verify that all connected cluster
peers have acknowledged the TOMBSTONE state. This prevents a scenario where a
partitioned peer still believes the dataset is ACTIVE and the reaper deletes
the authoritative record.

Consensus is considered reached when:
- All peers in the membership epoch that was active at destroy time have
- OR: `tombstone_min_age_commit_groups` has elapsed with no peer reporting a conflicting
  state (partition-tolerant fallback).

### 7.5 Reap operation

```
reap_dataset_record(dataset):
    1. Remove dataset entry from pool's dataset catalog B-tree.
    2. Delete the DestroyJobRecordV1.
    3. Release the dataset record's own metadata blocks (block pointer, TLV area).
    4. Log: "dataset <name> tombstone reaped; <bytes> definitively freed".
```

After reaping, the dataset no longer appears in `tidefsctl dataset list`. The
namespace name becomes available for reuse.

## 8. Destroy Metadata Records

### 8.1 DestroyJobRecordV1

Persisted in the dataset's system area as a TLV extension on the dataset record.

```
DestroyJobRecordV1 {
    magic: [u8; 4],            // "DSTR"
    version: u32,              // 1
    destroy_job_id: u64,       // Monotonically increasing job ID
    destroy_commit_group: u64,          // CommitGroup at which destroy was initiated
    destroy_flags: u32,        // DestroyFlags bitmask
    pinned_roots_count: u16,   // Number of pinned traversal roots
    pinned_roots: [TraversalRoot; pinned_roots_count],
    objects_total: u64,        // Estimated total objects (set at job start)
    objects_reclaimed: u64,    // Progress counter (updated atomically)
    bytes_reclaimed: u64,      // Progress counter (updated atomically)
    completion_commit_group: u64,       // 0 if not yet completed; commit_group on transition to TOMBSTONE
}
```

### 8.2 Dataset record state field

The dataset record's header gains a `state: u8` field, encoded as `DatasetStateV1`.
For datasets created before this design is implemented (prior-generation datasets), the
state field defaults to `0x01` (ACTIVE) when read.

V1 dataset record layout (new fields marked with *):

```
DatasetRecord {
    // ... existing fields (name, guid, parent, etc.) ...
    state: u8,                       // * DatasetStateV1 (new)
    feature_flags: DatasetFeatureFlagsV1,  // Per #1223
    destroy_job: Option<DestroyJobRecordV1>,  // * Present only in DESTROYING/TOMBSTONE
    // ... TLV extension area ...
}
```

## 9. Clone and Snapshot Interaction

### 9.1 Snapshot destroy

Snapshots are datasets with `parent != None`. Destroying a snapshot follows the
same lifecycle but with additional constraints:

- If the snapshot has clone children (datasets whose origin is this snapshot),
  destroy is refused with `EBUSY`. This is the ZFS-compatible behavior for V1.
- Future: `tidefsctl dataset promote <clone>` to detach a clone from its origin,
  allowing the snapshot to be destroyed.

### 9.2 Clone space accounting

Clone datasets share their origin's space domain. When a clone's origin is
destroyed:

1. The origin's blocks are not freed if any clone still references them
   (the clone holds block references through the origin's block tree).
2. The origin enters TOMBSTONE but its blocks remain allocated until all
   referencing clones are also destroyed.
3. The space accounting system (#1215) tracks this: each block carries a
   reference count, and blocks with refcount > 0 are not freed regardless of
   the origin dataset's state.

### 9.3 Destroy ordering

There is no enforced destroy ordering for clones and origins. Destroying a
clone first is safe (it releases its block references). Destroying the origin
first is safe (blocks persist until the last clone releases them). The reaper
defers physical block reclamation to the allocator's refcount system.

## 10. Cluster Lease Interaction

### 10.1 Multi-node consistency

In a multi-node deployment:

1. The DESTROYING state change is committed on the authority node (the node
   that owns the dataset's metadata).
   changed to DESTROYING, commit_group `<N>`".
3. All peer nodes that have this dataset mounted must:
   - Enter poison state for their local mounts (§5).
4. The authority node does not transition to TOMBSTONE until all connected
   peers have acknowledged (or the consensus timeout elapses).

### 10.2 Split-brain handling

If a network partition occurs during DESTROYING:

- The partition containing the authority node continues the destroy.
- Peers in the other partition retain their local view until the partition
  catch up.
- If a peer in the other partition attempts to mount the dataset, the mount
  succeeds locally but the dataset will be poisoned when the partition heals
- A peer that was partitioned during the ENTIRE destroy (DESTROYING through
  TOMBSTONE and reaping) will receive the dataset deletion from the

## 11. ZFS Prior-Art Comparison

The table below records design lessons and target behavior. It is not evidence
that the current TideFS implementation has parity with or superiority over ZFS,
nor that the async destroy, tombstone, abort, cluster consensus, or crash-resume
paths are production-ready. Any current product-facing comparison must route
through #875 claim ids and #928/#930 comparator evidence.

| Dimension | ZFS prior art | TideFS design target |
|---|---|---|
| Destroy model | Immediate: `zfs destroy` removes dataset inline during commit_group commit | Async with state machine: ACTIVE → DESTROYING → TOMBSTONE → reaped |
| Mount safety | DMU commit_group ordering prevents concurrent mount+destroy; dataset removal is immediate | Explicit state check on mount; DESTROYING/TOMBSTONE refuse mount with `ENOENT` |
| GC coordination | Spacemap incrementally tracks freed blocks; no separate GC | Pinned traversal roots prevent GC from reclaiming blocks the destroy job still needs |
| FUSE session handling | N/A (kernel module) | Poison state machine with configurable grace period; FORCE_UNMOUNT flag for immediate teardown |
| Observability | Dataset disappears from `zfs list` immediately | TOMBSTONE phase preserves dataset record with bytes/objects reclaimed until cluster consensus |
| Abort capability | No abort; destroy is irreversible once committed | DESTROYING → ACTIVE abort path with admin intervention; reclaimed blocks are not recovered |
| Cluster consensus | N/A (single-node ZFS) | TOMBSTONE reaper waits for peer acknowledgment before physical removal |
| Clone interaction | `zfs destroy` refuses if clones exist (`EBUSY`) | Same; future promote planned |
| Crash safety | ZIL replay ensures commit_group consistency; destroy is atomic within a commit_group | DestroyJobRecordV1 and pinned roots survive crashes; destroy worker resumes from last pinned root |

Design lessons carried forward:
- **Async destroy target**: keep large destroy work out of the foreground
  commit_group path by recording resumable state and processing reclamation in
  bounded background steps.
- **Tombstone target**: preserve a dataset record long enough for cluster
  acknowledgment and operator-visible reclamation accounting.
- **Abort target**: define an admin-mediated recovery window before physical
  reclamation makes the operation irreversible.

## 12. Implementation Plan

### Phase 1: State enum and mount gating
- Define `DatasetStateV1` enum in `tidefs-types-dataset`.
- Add `state: u8` field to dataset record header.
- Implement `DatasetOpenGate::check()` integrating feature flag check + state check.
- Unit tests: ACTIVE mounts OK, DESTROYING refuses, TOMBSTONE refuses, unknown state refuses.

### Phase 2: Transition to DESTROYING
- Implement `transition_to_destroying()`: write state, create DestroyJobRecordV1, pin roots.
- Implement poison notification channel.
- Unit tests: transition succeeds, pre-condition violations fail, EBUSY for clone children.

### Phase 3: Poison semantics
- Implement poison state machine in FUSE daemon.
- Grace period timer, drain queue, FORCE_UNMOUNT path.
- Integration test: mount → destroy → operations fail with EIO → FUSE session torn down.

### Phase 4: Pinned traversal roots
- Implement GC root set integration: `pinned_roots` treated as additional GC roots.
- Implement root removal as destroy worker progresses.
- Unit tests: GC doesn't reclaim pinned blocks, crash recovery re-pins roots.

### Phase 5: Destroy worker
- Implement async destroy worker: walk all roots, reclaim blocks, update progress.
- Implement DESTROYING → TOMBSTONE transition.
- Unit tests: full destroy lifecycle, progress reporting, partial completion.

### Phase 6: Tombstone reaper
- Implement background reaper task with minimum age and cluster consensus check.
- Implement `reap_dataset_record()`.
- Unit tests: reaper respects minimum age, reaper waits for consensus, reaper cleans up.

### Phase 7: Cluster integration
- Peer acknowledgment tracking.
- Split-brain handling.
- Integration test: multi-node destroy with partition and healing.

- `tidefs-xtask check-dataset-lifecycle`: runs the full test suite for all 7 phases.
- QEMU smoke test: create dataset, mount via FUSE, destroy, verify ENOENT on remount attempt.

## 13. Open Questions

1. **Grace period default**: Is 30 seconds appropriate? Should it scale with
   dataset size or active operation count?
2. **Tombstone minimum age**: Is 100 commit_groups (~100 seconds) the right default?
   This should be informed by measured cluster consensus propagation latency.
3. **Abort semantics**: Should DESTROYING → ACTIVE abort attempt to re-allocate
   already-freed blocks from the allocator? Current design says no (too complex,
   low value). Is this acceptable?
4. **TOMBSTONE visibility**: Should `tidefsctl dataset list` show TOMBSTONE
   datasets by default, or only with a `--all` flag?

Answers deferred to implementation review.
