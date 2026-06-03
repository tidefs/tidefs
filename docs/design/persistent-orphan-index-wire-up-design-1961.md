# Persistent Orphan Index — Wire-Up Integration Design

**Issue**: [#1961](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1961)
**Status**: design-spec
**Maturity**: design-spec — Rust implementation deferred to wire-up issues
**Lane**: storage-core
**Kind**: design
**Depends on**: [#1207](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1207) (orphan index design anchor),
  [#1621](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1621) (consolidated canonical design),
  [#1373](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1373) (Phase 1 core types),
  [#1383](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1383) (OrphanIndexRoot),
  [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267) (commit_group state machine),
  [#1212](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1212) (deferred cleanup),
  [#1219](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1219) (dataset lifecycle),
  [#1179](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1179) (background scheduler),
  [#1257](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1257) (B+tree CoW persistence),
  [#1220](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1220) (on-media format),
  [#1289](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1289) (polymorphic directory index),
  [#1232](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1232) (snapshot deadlist),
  [#1215](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1215) (space accounting)

---

## Abstract

This document specifies the integration ("wire-up") of the Phase 1 persistent
orphan index components into the full tidefs stack. Phase 1 delivered three
`no_std` crates (authority types, B+tree runtime, and IncrementalJob wrapper)
plus a `BackgroundOrphanReclamation` service stub. This design covers every
connection point required to make the orphan index a functional production
subsystem: the commit_group commit pipeline, initial mount recovery, O_TMPFILE lifecycle,
snapshot-aware extent reclamation via the deadlist, dataset destroy integration,
on-media format anchoring in `DatasetMetadataV1`, send/receive exclusion, and
the deferred cleanup work queue.

Each wire-up point is specified with its interface contract, algorithm,
error handling, and tradeoff rationale.

---

## 1. Architecture: Integration Surface

### 1.1 System context

```
┌──────────────────────────────────────────────────────────────────┐
│                        TideFS Node                                │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│  │ POSIX FUSE  │   │  COMMIT_GROUP Pipeline │   │  Background Scheduler │  │
│  │  Adapter    │──▶│  (#1267)      │   │  (#1179)              │  │
│  └─────────────┘   │  ┌─────────┐  │   │  ┌─────────────────┐  │  │
│        │           │  │  unlink  │──┼───┼──▶ OrphanRecoveryJob│  │  │
│        │           │  │  linkat  │  │   │  └────────┬────────┘  │  │
│        │           │  │  O_TMP   │  │   │           │           │  │
│        │           │  └────┬─────┘  │   │           ▼           │  │
│        │           └───────┼────────┘   │  ┌─────────────────┐  │  │
│        │                   │            │  │ Background      │  │  │
│        │                   ▼            │  │ OrphanReclaim   │  │  │
│        │           ┌──────────────┐     │  └────────┬────────┘  │  │
│        │           │  OrphanIndex │     │           │           │  │
│        │           │  (in-memory  │     │           ▼           │  │
│        │           │   B+tree)    │     │  ┌─────────────────┐  │  │
│        │           └──────┬───────┘     │  │ Deferred Cleanup│  │  │
│        │                  │             │  │ (#1212)         │  │  │
│        │                  │ B+tree CoW  │  └────────┬────────┘  │  │
│        │                  ▼             │           │           │  │
│        │           ┌──────────────┐     │           ▼           │  │
│        │           │ Object Store │     │  ┌─────────────────┐  │  │
│        │           └──────────────┘     │  │ Space Accounting│  │  │
│        │                                │  │ (#1215)         │  │  │
│        │                                │  └─────────────────┘  │  │
│        │                                │                       │  │
│        │           ┌──────────────┐     │  ┌─────────────────┐  │  │
│        │           │  Snapshot    │     │  │ Dataset Destroy │  │  │
│        │           │  Deadlist    │     │  │ (#1219)         │  │  │
│        │           │  (#1232)     │     │  └─────────────────┘  │  │
│        │           └──────────────┘     │                       │  │
│        └────────────────────────────────┴───────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Wire-up points

| # | Wire-up point | Source crate(s) | Target system | Data direction |
|---|---|---|---|---|
| W1 | unlink/linkat → orphan insert/delete | `tidefs-local-filesystem` | COMMIT_GROUP pipeline (#1267) | POSIX op → `OrphanIndex` mutation |
| W2 | O_TMPFILE create → orphan insert | `tidefs-local-filesystem` | COMMIT_GROUP pipeline (#1267) | `open(O_TMPFILE)` → `OrphanIndex` insert |
| W3 | O_TMPFILE linkat → orphan delete | `tidefs-local-filesystem` | COMMIT_GROUP pipeline (#1267) | `linkat()` → `OrphanIndex` delete |
| W4 | Mount recovery | `tidefs-local-filesystem` | `OrphanRecoveryJob` + `BackgroundOrphanReclamation` | On-disk B+tree → in-memory reclamation |
| W5 | Background reclamation | `BackgroundOrphanReclamation` | Deferred cleanup (#1212) | `OrphanIndex` scan → reclaim queue |
| W6 | Extent reclamation with deadlist gate | Deferred cleanup | Snapshot deadlist (#1232) | Orphan inode ID → extent free decision |
| W7 | Space accounting | Deferred cleanup | Space accounting (#1215) | Freed extents → `SpaceDelta` operations |
| W8 | Dataset destroy | Dataset lifecycle (#1219) | `OrphanIndex` force-sweep | Destroy job → orphan index drain |
| W9 | On-media format | `OrphanIndex` B+tree | `DatasetMetadataV1` (#1220) | `orphan_index_root` field |
| W10 | Send/receive | Dataset send/receive | `OrphanIndex` exclusion | Receiver rebuilds from inode table |
| W11 | B+tree persistence sync | `OrphanIndex` (in-memory) | Object store via commit_group flush | In-memory tree → CoW pages |

### 1.3 Crate dependency graph for wire-up

```
tidefs-types-orphan-index-core  (no_std, authority types)
         ▲                ▲
         │                │
┌────────┴───────┐  ┌────┴────────────────────┐
│ tidefs-orphan- │  │ tidefs-orphan-recovery-  │
│ index (no_std) │  │ job-core (no_std)        │
└────────┬───────┘  └────┬────────────────────┘
         │                │
         ▼                ▼
┌─────────────────────────────────────────────┐
│  tidefs-local-filesystem  (std, wire-up)    │
│  - BackgroundOrphanReclamation              │
│  - unlink/linkat commit_group hooks                  │
│  - mount recovery orchestration             │
│  - O_TMPFILE lifecycle wiring               │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  tidefs-local-object-store                  │
│  - B+tree CoW persistence (#1257)           │
│  - DatasetMetadataV1.orphan_index_root      │
└─────────────────────────────────────────────┘
```

---

## 2. Data Structures: Integration Contracts

### 2.1 OrphanCommitGroupOp: commit_group-batched mutation descriptor

```rust
/// Mutation to the orphan index that must be committed atomically
/// within the same commit_group as its causal event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanCommitGroupOp {
    /// Insert an inode into the orphan index (nlink became 0).
    Insert { inode_id: u64 },
    /// Delete an inode from the orphan index (nlink became >0, or inode destroyed).
    Delete { inode_id: u64 },
}
```

- Collected into a per-commit_group `Vec<OrphanCommitGroupOp>` during the commit_group quiesce phase.
- Applied to the in-memory `OrphanIndex` during commit_group commit phase 3 (quiesce fence).
- Flushed to object store alongside other B+tree mutations in phase 5 (flush).

### 2.2 OrphanIndexHandle: shared access token

```rust
/// Thread-safe handle to the in-memory orphan index for a dataset.
///
/// Owned by the dataset's `LocalFileSystem` instance.  Shared between
/// the POSIX op path (commit_group-driven insert/delete) and the background
/// services path (recovery scan, reclaim cleanup).
pub struct OrphanIndexHandle {
    /// The in-memory B+tree, protected by a mutex for concurrent access
    /// from commit_group worker threads and the background scheduler.
    pub tree: Arc<Mutex<OrphanIndex>>,
    /// Root pointer persisted in DatasetMetadataV1.
    pub root: OrphanIndexRoot,
    /// Recovery cursor, persisted per-dataset.
    pub recovery_cursor: OrphanCursor,
}
```

### 2.3 ReclaimQueueEntry: deferred cleanup descriptor

```rust
/// Entry in the deferred cleanup reclaim queue for an orphaned inode.
///
/// Produced by `BackgroundOrphanReclamation::tick()` and consumed by
/// the deferred cleanup work queue (#1212).
pub struct ReclaimQueueEntry {
    /// The orphaned inode ID to reclaim.
    pub inode_id: u64,
    /// Dataset that owns this orphan.
    pub dataset_id: DatasetId,
    /// Transaction group in which the entry was enqueued.
    pub enqueued_commit_group: u64,
    /// Number of retry attempts (incremented when deadlist blocks reclamation).
    pub retry_count: u32,
}
```

### 2.4 InitialRecoveryProtocol: mount-time recovery descriptor

```rust
/// Protocol for recovering orphans at mount time.
///
/// Determines whether the dataset is freshly opened (full recovery needed)
/// or was cleanly unmounted (no recovery needed).
pub struct InitialRecoveryProtocol {
    /// True if the dataset was not cleanly unmounted.
    pub needs_recovery: bool,
    /// The last committed recovery cursor position.
    pub cursor: OrphanCursor,
    /// Maximum recovery budget before yielding to user I/O.
    pub budget: OrphanRecoveryBudget,
}
```

### 2.5 DatasetMetadataV1 extension

The on-media `DatasetMetadataV1` record gains two fields:

```rust
pub struct DatasetMetadataV1 {
    // ... existing fields ...
    /// Root pointer for the orphan index B+tree.
    /// `OrphanIndexRoot::EMPTY` when no orphans exist.
    pub orphan_index_root: OrphanIndexRoot,
    /// Last-processed inode ID during crash recovery.
    /// 0 means no recovery has started or recovery is complete.
    pub orphan_recovery_cursor: u64,
}
```

---

## 3. Algorithms: Wire-Up Specifications

### 3.1 W1/W2/W3: COMMIT_GROUP commit pipeline integration

#### 3.1.1 Interface contract

The POSIX adapter (FUSE daemon) produces unlink, linkat, open(O_TMPFILE),
and close operations. These must result in `OrphanIndex` mutations that are
atomically committed within the same commit_group.

#### 3.1.2 Algorithm: unlink-path insert

```
fn handle_unlink(inode_id: u64, commit_group: &mut CommitGroupWriteHandle) -> Result<()> {
    // 1. Decrement nlink
    let nlink = inode_table.decrement_nlink(inode_id)?;

    // 2. If this was the last link, queue orphan insert
    if nlink == 0 {
        commit_group.queue_orphan_op(OrphanCommitGroupOp::Insert { inode_id });
    }

    // 3. Queue directory entry removal
    commit_group.queue_dir_op(DirOp::Remove { parent, name });

    Ok(())
}
```

#### 3.1.3 Algorithm: linkat-path delete

```
fn handle_linkat(inode_id: u64, commit_group: &mut CommitGroupWriteHandle) -> Result<()> {
    let nlink = inode_table.increment_nlink(inode_id)?;

    if nlink == 1 {
        // Inode was orphaned; now has a directory entry.
        // Remove from orphan index within same commit_group.
        commit_group.queue_orphan_op(OrphanCommitGroupOp::Delete { inode_id });
    }

    commit_group.queue_dir_op(DirOp::Insert { parent, name, inode_id });
    Ok(())
}
```

#### 3.1.4 COMMIT_GROUP commit phases

```
Phase 3 (Quiesce):
    1. Fence all in-flight orphan index operations.
    2. Sort and deduplicate OrphanCommitGroupOp vec.
        - Conflicting Insert+Delete for same inode_id → net Delete.
        - Duplicate Insert → collapse to single Insert.
    3. Apply to in-memory OrphanIndex:
        for op in commit_group.orphan_ops {
            match op {
                OrphanCommitGroupOp::Insert { inode_id } => orphan_index.lock().insert(inode_id),
                OrphanCommitGroupOp::Delete { inode_id } => orphan_index.lock().delete(inode_id),
            }
        }

Phase 5 (Flush):
    1. Serialize dirty B+tree pages to object store via CoW.
    2. Persist new orphan_index_root pointer.

Phase 6 (Sync):
    1. Write DatasetMetadataV1 with updated orphan_index_root.
    2. If recovery batch completed: update orphan_recovery_cursor.
```

#### 3.1.5 Crash consistency

- If crash occurs before phase 6: the commit_group group commit did not finalize.
  The previous DatasetMetadataV1 root is valid. OrphanIndex state is
  consistent with nlink state (both or neither committed).
- If crash occurs after phase 6: orphan index mutation and causal operation
  are both durable.

### 3.2 W4: Mount-time recovery

#### 3.2.1 Algorithm

```
fn mount_dataset(dataset: &Dataset, fs: &LocalFileSystem) -> Result<()> {
    // 1. Load DatasetMetadataV1
    let meta = load_dataset_metadata(dataset.id)?;

    // 2. Load orphan index from on-disk B+tree root
    let orphan_index = if meta.orphan_index_root.is_present() {
        load_bplus_tree(meta.orphan_index_root)?
    } else {
        OrphanIndex::new()
    };

    // 3. Determine recovery protocol
    let protocol = if meta.needs_recovery() {
        InitialRecoveryProtocol {
            needs_recovery: true,
            cursor: OrphanCursor { position: meta.orphan_recovery_cursor },
            budget: OrphanRecoveryBudget::default(),
        }
    } else {
        InitialRecoveryProtocol {
            needs_recovery: false,
            cursor: OrphanCursor::START,
            budget: OrphanRecoveryBudget::default(),
        }
    };

    // 4. Create OrphanIndexHandle
    let handle = OrphanIndexHandle {
        tree: Arc::new(Mutex::new(orphan_index)),
        root: meta.orphan_index_root,
        recovery_cursor: protocol.cursor,
    };

    // 5. Register background services
    let pending = Arc::new(Mutex::new(Vec::new()));
    let reclaim_svc = BackgroundOrphanReclamation::new(
        handle.tree.clone(), pending.clone()
    );
    scheduler.register(ServicePriority::Critical, reclaim_svc);

    // 6. If recovery needed, create OrphanRecoveryJob and enqueue it
    if protocol.needs_recovery {
        let job = OrphanRecoveryJob::new(job_id, handle.tree.lock().clone());
        scheduler.enqueue_incremental_job(job, protocol.budget);
    }

    Ok(())
}
```

#### 3.2.2 Recovery completion

When `OrphanRecoveryJob::step()` reports `is_complete`:
1. `orphan_recovery_cursor` is set to 0 (sentinel: recovery complete).
2. Dataset transitions to clean state.
3. `BackgroundOrphanReclamation` takes over for post-mount orphans.

### 3.3 W5: BackgroundOrphanReclamation tick

Existing implementation in `background_orphan_reclamation.rs` is mostly
complete. Wire-up additions needed:

#### 3.3.1 Pending-deletions drain into reclaim queue

```
fn drain_pending_deletions(
    pending: &Arc<Mutex<Vec<u64>>>,
    reclaim_queue: &mut ReclaimQueue,
    dataset_id: DatasetId,
    current_commit_group: u64,
) {
    let ids = pending.lock().unwrap().drain(..).collect::<Vec<u64>>();
    for inode_id in ids {
        reclaim_queue.push(ReclaimQueueEntry {
            inode_id,
            dataset_id,
            enqueued_commit_group: current_commit_group,
            retry_count: 0,
        });
    }
}
```

#### 3.3.2 Budget integration

`ServiceBudget` → `OrphanRecoveryBudget` conversion is handled by
`BackgroundOrphanReclamation::tick()`. The existing implementation
uses `max_items` correctly but should be enhanced to respect
`max_bytes` and `max_ms` for production use:

```
fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
    let ob = OrphanRecoveryBudget {
        max_orphans_per_tick: budget.max_items as usize,
        max_batch_size: 256,
        max_bytes_per_tick: budget.max_bytes,
        max_ms_per_tick: budget.max_ms,
        pressure_threshold: 0,
        pressure_budget_multiplier: 1,
    };
    // ... rest of tick ...
}
```

### 3.4 W6: Deadlist-gated extent reclamation

#### 3.4.1 Algorithm

```
fn reclaim_if_deadlist_clear(
    entry: &ReclaimQueueEntry,
    inode_table: &InodeTable,
    deadlist: &SnapshotDeadlist,
    space_accounting: &mut SpaceAccounting,
    orphan_index: &OrphanIndexHandle,
) -> ReclaimResult {
    // 1. Staleness guard: verify nlink == 0
    let inode = match inode_table.get(entry.inode_id) {
        None | Some(ref r) if r.nlink != 0 => {
            // Entry is stale; remove from orphan index and skip.
            orphan_index.tree.lock().delete(entry.inode_id);
            return ReclaimResult::SkippedStale;
        }
        Some(rec) => rec,
    };

    // 2. Build extent list from inode's extent tree
    let extents = extent_tree.get_extents(entry.inode_id)?;

    // 3. Check deadlist membership for each extent
    let mut blocked = false;
    for extent in &extents {
        if deadlist.contains(extent.object_key) {
            blocked = true;
            break;
        }
    }

    if blocked {
        // Retry on next tick; deadlist will shrink as snapshots are destroyed.
        return ReclaimResult::BlockedByDeadlist;
    }

    // 4. Free extents
    for extent in &extents {
        object_store.delete(extent.object_key)?;
        space_accounting.credit_freed(extent.size_bytes);
    }

    // 5. Remove from orphan index and inode table
    orphan_index.tree.lock().delete(entry.inode_id);
    inode_table.delete(entry.inode_id);

    ReclaimResult::Reclaimed {
        bytes_freed: extents.iter().map(|e| e.size_bytes).sum(),
    }
}
```

#### 3.4.2 Retry semantics

Entries blocked by deadlist are re-enqueued with `retry_count += 1`.
After `MAX_RETRIES` (default 256), an admin alert is raised and the
entry is skipped to prevent unbounded retry loops (e.g., a snapshot
that will never be destroyed).

### 3.5 W7: Space accounting integration

When `reclaim_if_deadlist_clear()` frees extents:

```
space_accounting.apply(SpaceDelta {
    dataset_id: entry.dataset_id,
    operation: SpaceOp::Free {
        bytes: extent.size_bytes,
        kind: SpaceKind::Data,
    },
    commit_group: current_commit_group,
});
```

### 3.6 W8: Dataset destroy integration

#### 3.6.1 Algorithm: DestroyOrphanSweep

```
fn destroy_orphan_sweep(
    orphan_index: &OrphanIndexHandle,
    inode_table: &InodeTable,
    object_store: &ObjectStore,
) -> Result<u64> {
    let mut bytes_reclaimed = 0u64;
    let idx = orphan_index.tree.lock();

    // Force-sweep: process ALL remaining orphans, skipping deadlist checks
    // since the dataset is being destroyed.
    let outcome = idx.batch_recover(
        OrphanCursor::START,
        OrphanRecoveryBudget::UNBOUNDED,
    );

    for inode_id in &outcome.inode_ids {
        if let Some(inode) = inode_table.get(*inode_id) {
            for extent in extent_tree.get_extents(*inode_id)? {
                object_store.delete(extent.object_key)?;
                bytes_reclaimed += extent.size_bytes;
            }
        }
        idx.delete(*inode_id);
    }

    Ok(bytes_reclaimed)
}
```

#### 3.6.2 Trigger

Called from `TraversalRootType::OrphanIndex` during destroy walk (#1219).
Called before the inode table and extent tree traversals to ensure no
orphan references survive into partial destroy.

### 3.7 W9: On-media format anchoring

#### 3.7.1 B+tree persistence

The in-memory `OrphanIndex` B+tree is synced to the object store via
the B+tree CoW persistence layer (#1257):

```
fn flush_orphan_index(
    index: &mut OrphanIndex,
    object_store: &ObjectStore,
) -> Result<OrphanIndexRoot> {
    // 1. Iterate dirty B+tree pages
    let dirty_pages = index.tree.dirty_pages();

    // 2. Write each page to object store via CoW
    let mut new_root = OrphanIndexRoot::EMPTY;
    for page in dirty_pages {
        let key = object_store.put_cow(page.data, page.level)?;
        if page.is_root {
            new_root = OrphanIndexRoot(key.as_u64());
        }
    }

    // 3. Mark pages clean
    index.tree.mark_clean();

    Ok(new_root)
}
```

#### 3.7.2 DatasetMetadataV1 serialization

The `orphan_index_root` and `orphan_recovery_cursor` fields are
serialized as part of `DatasetMetadataV1` (#1220). The on-disk layout:

```
DatasetMetadataV1 {
    ...
    orphan_index_root:    u64 (big-endian)  // OrphanIndexRoot::EMPTY = 0
    orphan_recovery_cursor: u64 (big-endian)  // 0 = no recovery in progress
}
```

### 3.8 W10: Send/receive exclusion

#### 3.8.1 Decision

The orphan index is **excluded** from send streams. The receiver rebuilds
the orphan index from the inode table after receive completes.

#### 3.8.2 Send-side algorithm

```
fn build_send_stream(dataset: &Dataset) -> SendStream {
    // Exclude orphan index from traversal roots.
    for root in dataset.traversal_roots() {
        if root.typ == TraversalRootType::OrphanIndex {
            continue;  // skip
        }
        // ... process other roots ...
    }
}
```

#### 3.8.3 Receive-side algorithm

```
fn post_receive_rebuild(dataset: &Dataset) -> Result<()> {
    // Scan inode table for nlink == 0 entries.
    let mut orphan_ids = Vec::new();
    for (inode_id, inode) in inode_table.iter() {
        if inode.nlink == 0 {
            orphan_ids.push(inode_id);
        }
    }

    // Rebuild orphan index from scan result.
    let mut index = OrphanIndex::from_inode_ids(&orphan_ids);

    // Persist the rebuilt index.
    let root = flush_orphan_index(&mut index, &object_store)?;
    update_dataset_metadata(dataset.id, |meta| {
        meta.orphan_index_root = root;
        meta.orphan_recovery_cursor = 0;
    })?;

    Ok(())
}
```

#### 3.8.4 Rationale

- **Simplicity**: The receiver already has the authority inode table.
  Scanning it once is O(nlink==0 inodes), which is bounded.
- **Avoids format coupling**: The orphan index B+tree layout may differ
  between send stream versions. Excluding it avoids versioning complexity.
- **Idempotency**: Rebuilding is deterministic from the inode table.

### 3.9 W11: B+tree persistence sync

#### 3.9.1 Sync protocol

The in-memory `OrphanIndex` must be synced to the object store before
`DatasetMetadataV1` is written in each commit_group commit:

```
fn commit_group_flush_phase(commit_group: &CommitGroupState, datasets: &[Dataset]) -> Result<()> {
    for ds in datasets {
        let mut idx = ds.orphan_index.tree.lock();
        if idx.tree.is_dirty() {
            let new_root = flush_orphan_index(&mut idx, &ds.object_store)?;
            ds.meta.orphan_index_root = new_root;
        }
        ds.meta.orphan_recovery_cursor = ds.orphan_index.recovery_cursor.position;
    }
}
```

#### 3.9.2 Lazy vs. eager sync tradeoff

| Strategy | Pros | Cons |
|----------|------|------|
| **Eager (every commit_group)** | Crash-consistent after every commit_group commit; no lost orphans | May write B+tree pages with minimal changes |
| **Lazy (every N commit_groups)** | Reduced CoW churn for write-heavy workloads | Up to N commit_groups of orphan state lost on crash; needs replay |

**Decision**: Eager sync. Orphan index mutations are infrequent (only at
unlink, linkat, O_TMPFILE create, close, and reclaim) and the B+tree CoW
mechanism already deduplicates unchanged pages. The consistency benefit
of eager sync outweighs the marginal write amplification.

---

## 4. Tradeoffs and Design Decisions

### 4.1 In-memory B+tree with commit_group flush vs. direct-to-disk

**Decision**: In-memory `OrphanIndex` B+tree, flushed to object store via
CoW at commit_group commit, with `DatasetMetadataV1.orphan_index_root` as the
durable root pointer.

**Rationale**: This matches the existing B+tree CoW persistence model
(#1257) used by the directory index, inode table, and extent maps.

**Tradeoff**: An in-memory `Arc<Mutex<OrphanIndex>>` means orphan index
mutations contend on a single mutex. For high-throughput unlink workloads
(e.g., `rm -rf` of a large tree), this could become a bottleneck.

**Mitigation**: The commit_group pipeline batches mutations (quiesce phase 3),
reducing lock contention to once per commit_group cycle rather than once per
unlink syscall. If profiling reveals contention, a lock-free concurrent
B+tree (e.g., `Arc<Mutex<>>` per leaf) can be introduced as a successor.

### 4.2 Recovery cursor granularity: per-batch vs. per-orphan

**Decision**: Per-batch cursor (current design). Cursor advances past
every scanned entry in a batch, not per-individual-orphan.

**Tradeoff**: On crash during recovery, up to `batch_size - 1` entries
may be re-scanned. Reclamation is idempotent, so this is safe. Per-orphan
cursor persistence would require one B+tree write per orphan, which is
prohibitive for datasets with millions of orphans.

### 4.3 Background reclamation vs. synchronous mount-time drain

**Decision**: Background service (`BackgroundOrphanReclamation`) with
deferred cleanup, not synchronous drain at mount.

**Tradeoff**: ZFS's synchronous `zfs_unlinked_drain()` blocks mount until
all orphans are reclaimed — minutes for millions of orphans. Background
service allows immediate mount with incremental reclamation interleaved
with user I/O. The tradeoff is that orphaned space is not instantly
available, but the `Critical` service priority ensures prompt reclamation.

### 4.4 Deferred staleness verification

**Decision**: Staleness checks (`nlink == 0` verification) are performed
in `BackgroundReclaim`, not in `batch_recover()` / `OrphanRecoveryJob::step()`.

**Rationale**: Verifying `nlink == 0` requires inode table access, which
may not be fully loaded during early mount-phase recovery. Deferring
avoids coupling orphan scanning to inode table hydration.

### 4.5 Per-dataset vs. pool-wide orphan index

**Decision**: Per-dataset orphan index. Each dataset has its own
`OrphanIndex` B+tree rooted in its `DatasetMetadataV1`.

**Tradeoff**: A pool-wide index would simplify destroy (no per-dataset
sweep), but would couple dataset state machines, complicate send/receive,
and make snapshot isolation harder. Per-dataset is the natural boundary
for all other dataset-scoped metadata (inode table, extent map, directory
index) and the orphan index follows this pattern.

### 4.6 Send/receive: exclude vs. transfer

**Decision**: Exclude orphan index from send stream; receiver rebuilds
from inode table.

**Tradeoff**: Transferring the orphan index would avoid a post-receive
scan but would couple the send stream to the B+tree internal format.
Rebuilding is O(nlink==0 inodes) — bounded and simpler.

### 4.7 O_TMPFILE insert timing

**Decision**: Insert `O_TMPFILE` inodes into the orphan index at
`open()` time, not at first write.

**Rationale**: The inode is allocated and would leak on crash even
without data. The only downside is a brief orphan index entry that
is deleted at `linkat()` or reclaimed at close/crash.

---

## 5. Error Handling

### 5.1 Poisoned mutex recovery

All `Arc<Mutex<OrphanIndex>>` accesses must handle poisoned locks:

```rust
fn recover_from_poison(idx: &Arc<Mutex<OrphanIndex>>) -> OrphanIndex {
    // On poison, replace with a fresh empty index.
    // Existing data is durable on disk; can be reloaded.
    let mut guard = idx.lock().unwrap_or_else(|poison| {
        warn!("orphan index mutex poisoned; replacing with empty index");
        poison.into_inner()
    });
    OrphanIndex::new()  // caller reloads from disk
}
```

### 5.2 Object store write failures during B+tree flush

If an object store write fails during commit_group phase 5 (B+tree flush):
- The commit_group commit is aborted.
- The in-memory orphan index retains all mutations.
- Writing thread retries the commit_group group commit.
- No orphan state is lost because the durable state in `DatasetMetadataV1`
  still references the previous root pointer.

### 5.3 Extent reclamation errors

If `reclaim_if_deadlist_clear()` encounters an I/O error freeing an extent:
- The orphan entry remains in the orphan index.
- The reclaim queue entry is re-enqueued.
- After `MAX_RETRIES` consecutive failures, the entry is skipped and logged
  as an admin-visible error.

---

## 6. Implementation Plan

### 6.1 Wire-up phases (deferred to individual issues)

| Phase | Wire-up point | Description | Estimated effort |
|-------|--------------|-------------|-----------------|
| W-A | W1, W2, W3 | COMMIT_GROUP integration: `OrphanCommitGroupOp` collection, quiesce application, flush persistence | Medium |
| W-B | W9, W11 | On-media format: `orphan_index_root` and `orphan_recovery_cursor` in `DatasetMetadataV1`; B+tree flush | Medium |
| W-C | W4 | Mount recovery: load B+tree from disk, create `OrphanRecoveryJob`, register `BackgroundOrphanReclamation` | Medium |
| W-D | W5 | Background reclamation drain into reclaim queue | Small |
| W-E | W6, W7 | Deadlist-gated extent reclamation with space accounting | Medium |
| W-F | W3 (O_TMPFILE) | O_TMPFILE lifecycle: insert at open, delete at linkat, crash-before-linkat test | Small |
| W-G | W8 | Dataset destroy: `destroy_orphan_sweep()` in destroy walk | Small |
| W-H | W10 | Send/receive: exclude from send, rebuild on receive | Small |

### 6.2 Ordering constraints

1. **W-A and W-B must ship together**: COMMIT_GROUP integration writes to the on-media format.
   Splitting them would leave the system writing to an undefined field.
2. **W-C depends on W-A + W-B**: Mount recovery requires the on-media format
   and commit_group persistence to be in place.
3. **W-D depends on W-C**: Background reclamation needs `OrphanIndexHandle`
   created at mount.
4. **W-E depends on W-D**: Deadlist gating needs reclaim queue entries.
5. **W-F can ship independently**: O_TMPFILE is an isolated code path.
6. **W-G depends on W-A + W-B**: Destroy needs the on-media format.
7. **W-H depends on W-A + W-B**: Send/receive needs the on-media format.

---


The xtask gate `tidefs-xtask check-orphan-index-wire-up` will verify:

1. **COMMIT_GROUP atomicity**: Crash injection during unlink+insert; verify orphan index
   and nlink are consistent after replay.
2. **Mount recovery**: Crash after commit_group commit with orphans; verify bounded-batch
   recovery completes and no orphan is leaked.
3. **Cursor resumption**: Crash mid-recovery; verify recovery resumes from last
   cursor position, not from START.
4. **O_TMPFILE**: Crash before linkat, after linkat, after close; verify orphan
   index state is correct in each case.
5. **Deadlist gating**: Create snapshot after orphan; verify extent is NOT freed.
   Destroy snapshot; verify extent IS freed on next tick.
6. **Staleness detection**: unlink→close→linkat sequence; verify staleness check
   detects nlink>0 and skips reclamation.
7. **Destroy sweep**: Destroy dataset with orphans; verify all orphans reclaimed
   and no content objects leaked.
8. **Send/receive**: Send dataset, receive on clean node; verify receiver orphan
   index matches sender after rebuild.
9. **Space accounting**: Verify `SpaceDelta` operations credit freed bytes
   correctly after each reclamation batch.
10. **Chaos test**: Randomized crash injection across all wire-up points;
    verify idempotent recovery with no data loss.

---

## 8. References

- [#1207](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1207) — Original orphan index design anchor (`docs/PERSISTENT_ORPHAN_INDEX_DESIGN.md`)
- [#1621](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1621) — Consolidated canonical design (`docs/design/persistent-orphan-index-consolidated-design.md`)
- [#1373](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1373) — Phase 1 core types implementation
- [#1383](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1383) — OrphanIndexRoot type
- [#1546](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1546) — BackgroundReclaim stub
- [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267) — Canonical commit_group state machine
- [#1212](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1212) — Deferred cleanup work queues
- [#1215](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1215) — Space accounting model
- [#1219](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1219) — Dataset lifecycle
- [#1220](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1220) — On-media format strategy
- [#1232](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1232) — Snapshot deadlist
- [#1257](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1257) — B+tree CoW persistence
- [#1289](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1289) — Polymorphic directory index
- [#1179](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1179) — Background service scheduler

---

*This document is the wire-up integration design-spec for the persistent orphan
index (Issue #1961). It specifies how the Phase 1 components connect to the
broader tidefs stack. The consolidated canonical design (#1621) remains the
authority for core architecture, data structures, and algorithms.*
