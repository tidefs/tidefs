# Canonical commit ordering and multi-phase commit_group state machine (v1.0-draft)

Maturity: **spec-draft** — formal design document per issue #1267.

## Source

v0.262 design book §"Writeback and flush model" + §"Commit grouping".
The v0.262 Python implementation (v0.135) implemented a detailed commit_group state
machine with explicit ordering contract. This document formalizes that
design for the Rust implementation.

## Seven-step canonical commit ordering

```
Step 1: APPEND data records (extent payloads / shards)
          │
Step 2: FLUSH data journal (fsync/fdatasync)
          │
Step 3: APPEND metadata updates (extent maps, inodes, catalogs)
          │
Step 4: APPEND commit record (METADATA_COMMIT_V1 or POOLMAP_COMMIT_V1)
          │
Step 5: FLUSH metadata journal
          │
Step 6: UPDATE checkpoint pointer copies in system area (slice-0)
          │
Step 7: FLUSH system area writes
```

### Invariant

A pointer is never persisted before what it points to.

- Steps 1-2 ensure data payloads are durable before metadata references
  them, preventing metadata from pointing to unflushed data.
- Steps 5-7 ensure the commit record is durable before the checkpoint
  pointer makes it reachable, preventing torn commits on crash.
- Steps 6-7 ensure the checkpoint pointer itself is durable before any
  reader trusts it.

### Durability classes

| Class | Steps | Trigger |
|-------|-------|---------|
| MetadataOnly | 3-7 | mkdir/rename/unlink — no data pages dirty |
| DataAndMetadata | 1-7 | Writes — data payloads present |
| ForcedDurability | 1-7 | fsync/O_DSYNC — immediate, bypasses batching |

- **MetadataOnly**: Omits steps 1-2. The intent log is empty (no data
  payloads acknowledged), so only metadata needs persistence. This is
  the fast path for namespace mutations.
- **DataAndMetadata**: Full 7-step pipeline when data pages are dirty.
- **ForcedDurability**: Same 7-step pipeline but triggered immediately
  (no batching delay). Used for fsync(2) and O_DSYNC semantics.

## Multi-phase commit_group state machine

```
           ┌─────────────────────────────────────────┐
           │                                         │
           ▼                                         │
    ┌──────────┐    trigger     ┌──────────┐    inflight=0    ┌──────────┐
    │   OPEN   │ ─────────────► │ QUIESCE  │ ───────────────► │   SYNC   │
    │          │                │          │   or timeout      │          │
    └──────────┘                └──────────┘                  └──────────┘
         ▲                                                        │
         │                                                        │
         └────────────────────────────────────────────────────────┘
                              complete_sync()
```

### OPEN phase

- Accept new writes into the current commit_group.
- Accumulate dirty bytes (`self.commit_group.dirty_bytes`) and dirty operation
  count (`self.commit_group.dirty_ops`).
- Track dirty inodes and extent maps.
- Writers may be throttled via back-pressure when `dirty_bytes`
  exceeds `commit_group_dirty_max_bytes`.
- Evaluate auto-sync triggers at operation boundaries and maintenance
  ticks.

### QUIESCE phase

- Stop accepting new writes into this commit_group.
- New writes go to the next commit_group (still Open, written to intent log).
- Wait for in-flight writes to complete (`inflight_writes → 0`).
- Has a configurable timeout (`commit_group_quiesce_timeout_secs`): if in-flight
  writes don't drain in time, sync proceeds (they'll be captured in
  the next commit_group).
- Back-pressure is released: the next commit_group is now accepting.

### SYNC phase

- Execute the 7-step commit ordering.
- Publish the commit record.
- Update the checkpoint pointer.
- Dirty buffers become clean.
- Advance `current_commit_group` and reset counters.
- Return to OPEN.

## Auto-sync trigger hierarchy

Evaluated at operation boundaries and maintenance ticks. Higher-priority
triggers are checked first:

```
1. commit_group_dirty_max_bytes   (hard byte threshold — back-pressure)
2. commit_group_target_ops        (op-count threshold)
3. commit_group_target_bytes      (soft byte threshold)
4. commit_group_target_secs       (time threshold)
5. explicit fsync        (ForcedDurability — immediate)
```

| Trigger | Config key | Default | Behavior |
|---------|-----------|---------|----------|
| ByteMaximum | `commit_group_dirty_max_bytes` | 512 MiB | Throttle writers; force sync |
| OpCount | `commit_group_target_ops` | 2048 | Trigger on dirty op count |
| ByteTarget | `commit_group_target_bytes` | 64 MiB | Trigger on dirty byte count |
| TimeTarget | `commit_group_target_secs` | 5s | Trigger on elapsed commit_group time |
| ExplicitSync | — | — | Immediate ForcedDurability |

### Back-pressure

When `dirty_bytes > commit_group_dirty_max_bytes`:
1. `write_started()` is still accepted for in-flight writes, but
2. `record_write()` returns `false` for new writes.
3. The writer must either retry after the next sync, or return
   `ENOSPC`-equivalent pressure back to the caller.
4. Once sync completes, dirty counters reset and back-pressure lifts.

## Deterministic clock injection

For crash testing and determinism, the `CommitGroupStateMachine` is generic over
a `Clock` trait:

- `SystemClock`: Delegates to `std::time::Instant::now()` — production use.
- `FixedClock`: Returns a fixed `Instant` that can be advanced
  programmatically — used for deterministic time-based trigger tests.

## Recovery contract

On crash plus reopen:

1. Read checkpoint pointer from system area (slice-0).
2. If the checkpoint pointer is valid: load committed state directly.
3. If the checkpoint pointer is torn/corrupt: fall back to journal
   scanning (per #1224 torn-commit recovery).

The 7-step ordering guarantees that the checkpoint pointer is only
updated AFTER the commit record is flushed, so a valid checkpoint
pointer always references a complete, durable commit.

## Crash-injection testing matrix

The crash injection harness (#1230) must test crashes at each of the
7 steps to verify recovery behavior:

| Crash after step | Expected recovery |
|-----------------|-------------------|
| 1 (APPEND data) | No effect — next commit retries |
| 2 (FLUSH data) | Data durable but not referenced — safe |
| 3 (APPEND metadata) | Metadata written, no commit record — rolled back |
| 4 (APPEND commit) | Commit written, no checkpoint — recovered via journal (#1224) |
| 5 (FLUSH metadata) | Commit durable, stale checkpoint — next commit_group covers |
| 6 (UPDATE checkpoint) | Partial checkpoint update — fallback to journal |
| 7 (FLUSH system area) | All durable — clean recovery |

## Configuration presets

| Preset | Ops | Bytes | Max Bytes | Time | Use case |
|--------|-----|-------|-----------|------|----------|
| `conservative()` | 16 | 64 KiB | 256 KiB | 1s | Correctness testing |
| `default()` | 2048 | 64 MiB | 512 MiB | 5s | General workloads |
| `throughput()` | 16384 | 256 MiB | 2 GiB | 30s | Bulk/streaming |

## Relationship

- Implements durability contract for #1190 (G2 transaction model).
- Fast path for sync writes via #1252 (intent log / LOG_DEVICE).
- Crash recovery via #1224 (torn-commit recovery).
- Crash testing via #1230 (crash injection harness).
- Scheduling via #1241 (commit_group sync in CONTROL lane).
- Blocked by #1213 (VFS Engine API contract — now delivered).

## Implementation

The commit_group state machine is implemented in
`crates/tidefs-local-filesystem/src/commit_group.rs` and wired into
`LocalFileSystem::do_commit()` and `LocalFileSystem::sync_write_intent()`.

Key types:
- `TxnGroupId(u64)` — monotonically increasing commit_group identifier.
- `CommitGroupPhase` — `Open | Quiesce | Sync`.
- `CommitGroupCommitStep` — 7 canonical steps with label and ordering helpers.
- `DurabilityClass` — `MetadataOnly | DataAndMetadata | ForcedDurability`.
- `CommitGroupConfig` — trigger thresholds with presets.
- `CommitGroupStateMachine<C: Clock>` — generic state machine with phase transitions.
- `CommitGroupCommitLog` — record of completed SYNC for diagnostics.

Maintenance tick (`commit_group_maintenance_tick`) is exposed for periodic
evaluation from the CONTROL lane scheduler (#1241).
