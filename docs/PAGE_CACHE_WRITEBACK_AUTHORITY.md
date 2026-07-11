# Page Cache Writeback Authority

Maturity: current authority document for TFR-008 and GitHub issues #511 and
#1065.

Authority claim path: `local.vfs.page_cache_writeback_authority.v1`.

Decision id: `tfr-008.page_cache_writeback_recovery_authority.v1`.

This document defines the contract that TideFS implementations must satisfy
when cached file bytes become dirty, are written back, become clean, interact
with `fsync`/`syncfs`, and recover after a crash. It is a specification and
authority boundary only. It does not implement writeback behavior, wire runtime
enforcement, or validate any present-tense crash-safety claim.

The claim path above is a named authority path, not a validated product claim.
It must remain blocked until the implementation and validation evidence named
below exist.

## Scope

This authority covers:

- page-cache and folio-backed dirty data created by buffered writes;
- shared writable mmap dirties that must become file data;
- writeback batches that move dirty bytes toward storage authority;
- caller-visible barriers such as `fsync`, `fdatasync`, `syncfs`, `flush`, and
  `msync(MS_SYNC)`;
- crash recovery ordering between page-cache state, intent-log records, and
  committed roots.

This authority does not cover private mmap copy-on-write bytes, read-only clean
cache population, direct I/O semantics beyond cached-range reconciliation, or
distributed replica placement. Those paths may reference this contract only
when they create, drain, invalidate, or observe shared dirty file data.
`docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` owns the page-cache invalidation
trigger surface, stale-generation rule, and FUSE/kernel/cluster coherency
lease model.

## Authority Terms

| Term | Authority meaning |
|---|---|
| Page-cache mirror | A non-authoritative cached copy of file bytes. Clean cached bytes may serve reads, but storage and replay authority decide post-crash truth. |
| Dirty page | A page, folio, or byte range whose accepted bytes differ from the currently committed storage view and are not yet covered by a completed writeback authority. |
| Dirty epoch | The ordering token that groups dirty bytes with their inode, byte range, writer class, and storage mutation boundary. |
| Writeback batch | A sealed set of dirty ranges selected for storage writeback under a specific trigger and ordering boundary. |
| Writeback pending | The state after a dirty range is selected for writeback and before completion or retry is recorded. |
| Clean transition | The transition that makes a formerly dirty range evictable as clean cache after the required storage and recovery ordering has completed. |
| Invalidation intent | A coherency event that removes or fences stale clean cache and waits for dirty/writeback state instead of discarding it. |
| Recovery authority | The committed-root plus intent-log replay path that decides which bytes exist after restart. |
| Projection | A runtime view, adapter, kernel cache, or validation consumer that observes the authority but cannot strengthen the durability or coherency guarantee on its own. |
| Canonical owner | The crate whose data model decides the durable or coherency fact for the relevant scope. |

## Current Authority

The current authority is narrow:

- Page-cache bytes are never the durable source of truth. They are a mirror
  that can be clean, dirty, writeback-pending, invalidation-waiting, or
  poisoned by writeback error.
- Clean page-cache state alone is not evidence that data reached stable
  storage. `fsync`, `fdatasync`, `syncfs`, `flush`, and `msync(MS_SYNC)` must
  wait for the storage and recovery boundary required by their scope.
- Dirty and writeback pages must not be silently invalidated. Current
  `tidefs-cache-coherency` invalidation is allowed to evict clean, unpinned
  entries; dirty and writeback entries are preserved for the owning writeback
  authority.
- Intent-log records, transaction markers, flush markers, fsync markers, and
  write-intent acknowledgments are ordering evidence. They do not by
  themselves mark a page-cache range clean; the writeback owner must join them
  with content/metadata persistence and recovery rules.
- TFR-008 remains open. Issue #443 (cache-coherency/writeback proof, closed)
  and issue #445 (intent-log replay idempotency, closed) provided focused-unit
  evidence now consumed by this authority document. Issue #486 (local VFS
  write/fsync crash evidence, closed) provided bounded OpFsyncBeforeFlush
  runtime crash evidence consumed by `local.vfs.write_fsync_crash.v1`. Issue
  #1065 records the broader survey, boundary decision, and follow-up map.
  Mounted writeback, mmap, and broader durability evidence remain future work.

## Evidence Reviewed For Issue #1065

Documentation reviewed:

- `docs/REVIEW_TODO_REGISTER.md` records that recovery, fsync, dirty writeback,
  mmap, page-cache invalidation, and lease coherency are still split across
  several mechanisms.
- `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` decides the invalidation trigger
  surface, stale-generation rule, and FUSE/kernel/cluster lease model.
- The `page_cache_writeback_mmap_acceptance_cases()` source binding is a
  source-model input. Current mmap/writeback status lives in this authority
  document, `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`,
  `validation/claims.toml`, and live GitHub issues; this does not claim live
  mounted mmap/writeback closure.
- `validation/claims.toml` and `docs/CLAIM_REGISTRY.md` keep
  `local.vfs.page_cache_writeback_authority.v1` blocked pending mounted
  writeback, mmap coherency, no-hidden-queue, and broader durability evidence.

Current source reviewed:

- `crates/tidefs-cache-core/src/page_cache.rs` defines the shared page state
  machine: clean, dirty, writeback, locked, and pinned flags; dirty-page
  indexes; clean-only invalidation; writeback start, completion, and abort.
- `crates/tidefs-local-filesystem/src/page_cache/mod.rs` is a derived local
  cache with a local dirty-page tracker, clean invalidation, and reclaim inputs.
- `crates/tidefs-local-filesystem/src/writeback.rs`,
  `dirty_page_tracker.rs`, and `writeback_daemon.rs` split dirty accounting,
  exact dirty byte ranges, background scheduling, fsync coordination, and flush
  target dispatch.
- `crates/tidefs-local-filesystem/src/fuse_fsync.rs`,
  `commit_group.rs`, `intent_log.rs`, `recovery.rs`, and `crash_recovery.rs`
  contain the local fsync/fdatasync/syncfs dispatch, seven-step commit-group
  ordering, sync-write and mmap intent kinds, committed-root selection,
  LOG_DEVICE handling, and crash-boundary classification surfaces.
- `crates/tidefs-intent-log/src/record.rs` and `replay.rs` define the generic
  intent-log record set, transaction markers, barrier markers, and idempotent
  replay engine.
- `crates/tidefs-cache-coherency/src/lib.rs`,
  `crates/tidefs-invalidation-feed/src/lib.rs`, `crates/tidefs-lease/`, and
  `crates/tidefs-lease-manager/` define invalidation messages, wait policies,
  range/inode/dataset scopes, lease domains, lease epochs, generation tracking,
  and dirty-drain/fence behavior for clustered coherency.
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` and
  `mmap_coherency.rs` are FUSE projections: writeback-cache mode still writes
  through to the engine before replying, tracks daemon dirty ranges, reconciles
  direct writes, exposes FUSE fsync/flush behavior, and has mmap invalidation
  generation callbacks.
- `kmod/src/kernel_types.rs` and
  `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_shim.c` are kernel
  projections: kmod traits expose fsync, syncfs, writeback_folios, mmap,
  invalidate callbacks, and committed-root barriers; the mounted C shim waits
  page writeback before engine fsync and admits mmap only through the
  engine-backed `generic_file_mmap()` path.

## Surveyed Surfaces

| Surface | Current source | Authority classification |
|---|---|---|
| Committed-root recovery | `crates/tidefs-local-filesystem/src/recovery.rs`, `crash_recovery.rs`, root-slot helpers, commit-group and txg replay paths | Canonical local durability input. Recovery chooses committed roots and replays durable intents; in-memory cache state is gone after crash. |
| Intent-log replay | `crates/tidefs-intent-log/`, local `intent_log.rs`, LOG_DEVICE file handling | Canonical replay input, but marker records and acknowledgments are ordering evidence, not clean-page authority. |
| Dirty accounting | Local `DirtySet`, range `DirtyPageTracker`, local page-cache tracker, FUSE dirty-state ranges, kmod live write buffer | Split implementation state. The authority target is one observable dirty lifecycle; current copies are projections or partial indexes until unified. |
| Writeback scheduling | `tidefs-cache-core::PageCache`, local `WritebackDaemon`, FUSE writeback scheduler/cache, kmod `writeback_folios` and C address-space callbacks | Cache-core owns non-durable page state transitions. Local/FUSE/kmod schedulers consume that authority and must not mark clean before storage or replay authority completes. |
| `fsync` and `fdatasync` | Local `DirtyFlush`, `dispatch_engine_fsync`, `fdatasync_inode`, local commit-group and sync gates, FUSE fsync handler, kmod file fsync | Caller-visible durability barriers. They must wait for dirty ranges, intent/replay coverage, and committed-root or equivalent receipt authority. |
| `syncfs`, flush, and clean unmount | Local `flush_all`, `sync_all`, commit-group close, FUSE flush/syncfs, kmod syncfs and unmount barrier | Filesystem or mount-scope barriers. They cannot replace single-inode fsync correctness with unbounded global flushing as the default design. |
| Mmap | Local `SharedMmapMsync` intent kind, FUSE `MmapCoherency`, kmod `generic_file_mmap()` path and C address-space callbacks | Shared writable mmap dirties must join writeback authority. Private COW bytes are outside this authority. Cross-node mmap remains a non-claim without a lease manager. |
| Page-cache invalidation | `tidefs-cache-core`, local page caches, FUSE page/read/writeback caches, kmod filemap invalidation helpers | Invalidation may evict clean mirrors and fence dirty/writeback overlap. It cannot decide durability. |
| Stale-generation fencing | `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`, lease-manager generation tracking, FUSE/kmod invalidation projections | Canonical coherency rule. A cached byte may be served only while its dataset/inode/range/lease generation still matches current authority. |
| Cluster lease/revocation | `tidefs-cache-coherency`, `tidefs-invalidation-feed`, `tidefs-lease`, `tidefs-lease-manager` | Canonical coherency event and lease epoch authority. It drains, transfers, rejects, or fences dirty overlap before conflicting grants or epochs publish. |

## Authority Model Comparison

| Model | Description | Strengths | Weaknesses | Decision |
|---|---|---|---|---|
| Kernel-resident page cache with userspace writeback | Linux/FUSE or kmod page cache holds dirty bytes while userspace or an engine path later writes them to storage. | Fits buffered I/O and mmap mechanics, uses existing kernel writeback hooks, and can reuse FUSE/kmod cache notifications. | Page-cache state vanishes on crash, FUSE and kmod have different callback surfaces, cross-node invalidation still needs leases, and clean kernel pages cannot prove storage durability. | Projection only. Kernel/FUSE caches may hold and expose bytes, but they do not own durability or stale-generation truth. |
| Userspace-resident cache with kernel lease callbacks | TideFS keeps the primary dirty/cache state in userspace crates and drives kernel cache invalidation through FUSE notifications, kmod callbacks, and lease messages. | Centralizes local dirty accounting and cluster invalidation policy, and fits the existing `tidefs-cache-core` and lease-manager crates. | Pure userspace ownership cannot satisfy the full-kernel product boundary, and callback failure must still fail closed through generation fences. | Partial local authority. Useful for FUSE/userspace mode, but kernel-mode projections must consume the same contract rather than depend on a daemon for mounted operation. |
| Storage/replay authority with cache projections | Committed roots, replayable intent records, and explicit barrier receipts decide durability. Cache-core, FUSE, kmod, and cluster lease paths are projections that must prove their generation and dirty/writeback state before serving or cleaning bytes. | Survives crash, applies to FUSE and kmod, gives clustered leases a clear drain/fence target, and keeps claim-gate evidence source-qualified. | Requires implementation work to remove duplicated dirty indexes and to prove mounted runtime paths. | Chosen boundary for TFR-008. |

## Chosen Authority Boundary

TideFS uses storage/replay authority with cache projections.

Canonical local durability authority belongs to
`crates/tidefs-local-filesystem/` plus `crates/tidefs-intent-log/`:
committed-root publication, commit-group ordering, sync barriers, durable
intent-log append/replay, LOG_DEVICE handling, and mount recovery decide which
bytes exist after restart. These crates must converge on one dirty lifecycle
before the claim path can validate.

Canonical page-state authority for non-durable cache transitions belongs to
`crates/tidefs-cache-core/`. It may decide whether a cached page is clean,
dirty, writeback-pending, pinned, or evictable, but it does not decide that the
bytes are durable after crash.

Canonical cache-coherency authority belongs to `crates/tidefs-cache-coherency/`,
`crates/tidefs-invalidation-feed/`, `crates/tidefs-lease/`, and
`crates/tidefs-lease-manager/`. Those crates own invalidation message shape,
wait policy, lease epoch, membership epoch, and generation advancement. They
decide when clean mirrors are stale and when dirty/writeback overlap must be
drained, transferred, rejected, or fenced.

The following crates and paths are projections or consumers:

- `apps/tidefs-posix-filesystem-adapter-daemon/`: FUSE write, flush, fsync,
  writeback-cache, mmap-coherency, and notification projection.
- `kmod/` and `crates/tidefs-kmod-posix-vfs/`: kernel address-space,
  writeback, fsync, syncfs, mmap, invalidation, and committed-root projection.
- `crates/tidefs-local-filesystem/src/page_cache/`, hot-read cache, inode
  cache, and adapter read caches: non-authoritative read/cache acceleration.
- `validation/`, `docs/CLAIM_REGISTRY.md`, and `validation/claims.toml`: claim
  consumers. They may record evidence only after the runtime authority is
  implemented and validated.

The chosen boundary covers the issue's required edges as follows:

- Dirty-page tracking: one observable lifecycle owns dirty byte ranges from
  accepted write or shared mmap dirty through writeback, retry/error, and clean
  transition. Existing duplicate dirty indexes are implementation debt.
- Writeback ordering: writeback completion requires content persistence,
  metadata reachability, relevant intent-log/barrier ordering, and generation
  reconciliation.
- `fsync`/`fdatasync`: successful barriers mean every in-scope dirty range has
  reached a recovery-safe boundary or the caller has received/retained an error.
- Mmap consistency: shared writable mmap dirties join the same dirty/writeback
  authority. Private mmap COW bytes are outside the published file-data
  contract.
- Invalidation triggers: invalidation removes clean stale mirrors and fences
  dirty/writeback overlap for the writeback authority. It never marks dirty
  bytes durable.
- Stale-generation fencing: reads, mmap faults, and writeback completion must
  prove dataset, inode, range/file-size, and lease generation before trusting a
  cached byte or clean transition.
- Lease/revocation: conflicting write leases and membership epochs must wait
  for clean eviction or dirty drain, or publish a typed fence/error, before
  old cached bytes can be treated as inactive.

## Explicit Non-Claims

This authority does not claim:

- DAX or direct persistent-memory coherence without explicit kernel support.
- Cross-node mmap consistency without a cluster lease manager and runtime
  invalidation/drain evidence.
- Production crash safety for mounted FUSE or kmod writeback before mounted
  runtime crash evidence exists.
- That FUSE writeback-cache mode may acknowledge bytes that only live in
  daemon-side dirty trackers.
- That `Flush`, `Fsync`, `WriteIntentAck`, or transaction markers alone make a
  page-cache range clean.
- That a global pool-wide flush is the normal answer to per-inode fsync
  correctness.
- That closed focused issues #443, #445, #486, #753, or #754 validate the
  broader TFR-008 claim path.

## Aspirational Design Not Yet Authority

The following are required future behavior, not current proof:

- A single runtime state machine that records every dirty page lifecycle edge.
- Runtime enforcement that every dirty page is admitted through budgeted dirty
  work and no hidden writeback queue can bypass the performance contract.
- Crash-injection evidence proving that dirty bytes acknowledged by `fsync`
  either survive in the committed root or replay exactly once from the
  intent log.
- Mounted FUSE, mounted kernel, mmap, direct write, and syncfs paths using one
  shared writeback authority rather than independent local conventions.
- A validated claim registry entry for
  `local.vfs.page_cache_writeback_authority.v1`.

## Dirty Page Lifecycle

### 1. Clean visible

A page-cache entry starts as clean when it is populated from an authoritative
storage or replay view. Clean entries may be served to readers and may be
evicted by memory pressure or coherency invalidation.

A clean entry becomes stale when its inode/range anchor is superseded by
truncate, hole-punch, collapse/insert range, direct write reconciliation,
lease revocation, rename/unlink cutover, or membership epoch transition.
Stale clean entries must be invalidated before they can serve new reads.

### 2. Mark dirty

Buffered writes and shared writable mmap faults that change file-visible bytes
must mark the affected page or byte range dirty before the mutation can be
treated as accepted by TideFS. Mark-dirty must capture at least:

- inode and byte range;
- writer class: buffered write, shared mmap, direct-write reconciliation, or
  another named class;
- dirty epoch or equivalent ordering token;
- intent-log requirement for the byte range;
- commit-group or transaction boundary that will own publication;
- admission/accounting information for dirty bytes and dirty operations.

Mark-dirty makes the page-cache entry non-evictable as clean. Invalidation may
fence it, but must not drop it as if it matched storage.

### 3. Writeback eligibility

A dirty range is eligible for writeback only when:

- the range is still anchored to the current inode/file identity;
- no incompatible truncate, invalidation, lease revocation, or generation
  transition is in progress;
- the writeback owner can snapshot the bytes to be written;
- the dirty work is admitted under the appropriate queue and budget;
- the target storage and intent-log path can accept the write or return a
  classified retry/error.

Eligibility does not imply completion. A range selected by memory pressure can
remain non-durable until the fsync or commit-group ordering boundary completes.

### 4. Writeback pending

Starting writeback seals the selected ranges into a writeback batch. While the
batch is pending:

- readers may observe the cache under normal VFS visibility rules, but the
  pending batch is not a durability claim;
- invalidation must wait, retry, or classify the overlap rather than deleting
  the dirty bytes;
- failures must re-dirty the range or poison it with a mapping/storage error;
- the batch must remain tied to its dirty epoch and intent-log/commit boundary.

### 5. Writeback completion

Writeback completion requires all authority edges for the trigger scope:

- the selected bytes are written to the intended content, object, extent, or
  lower storage authority;
- metadata required to find those bytes after recovery is committed or covered
  by replayable intent records;
- the relevant intent-log records, write-intent acknowledgments, and
  transaction markers have the durability required by the trigger;
- errors have been surfaced to the caller or retained in page/mapping state.

Only after those edges complete may the range leave writeback-pending state.

### 6. Clean transition

A dirty range may transition to clean only when the writeback owner has
recorded successful completion for the range and the range still belongs to the
same inode/file identity that was written back.

If the inode identity, size, extent layout, generation, or lease epoch changed
while writeback was pending, the completion must be reconciled before clean
state is visible. The range may need invalidation, retry, or a mapping error
instead of a clean transition.

## Writeback Triggers

### Memory pressure

Memory pressure may start background writeback for eligible dirty ranges.
Memory-pressure writeback may reduce cache pressure, but it does not satisfy a
caller durability barrier unless it also completes the ordering required for
that barrier. If it fails, the affected range must stay dirty, be retried, or
carry a visible writeback error.

### `fsync`, `fdatasync`, and `syncfs`

`fsync` is a caller-visible durability barrier for the target file handle.
`fdatasync` may omit metadata that is not required to retrieve the file data,
but it must include metadata needed for the synced bytes to survive recovery.
`syncfs` applies the same rule to the filesystem or dataset scope chosen by
the implementation.

These triggers must wait for every dirty range in scope to reach writeback
completion or must return an error. They must also order the relevant
intent-log and commit-group state so recovery cannot lose bytes that the
barrier acknowledged.

### Commit-group close

Closing a commit group seals the dirty epochs and writeback batches that belong
to that group. A commit-group close must not publish a committed root, durable
transaction marker, or clean-page transition for data whose required writeback
or replay intent is incomplete.

Commit-group boundaries should remain dataset/inode scoped where possible.
This document does not authorize pool-wide flushing as the default answer to
single-inode fsync correctness.

### Explicit flush

Explicit flush includes close-path `flush`, `msync(MS_SYNC)`, direct-write
cache reconciliation, unmap/truncate invalidation drains, and operator-driven
flush commands. An explicit flush may be weaker than `fsync` only if the
caller-visible API permits that weaker guarantee. It still must not drop dirty
or writeback pages as clean cache.

## Ordering Contract

### Relative to `fsync`

Successful `fsync` means all dirty page-cache bytes in the file's fsync scope
have reached a recovery-safe boundary. That boundary may be a committed storage
root, a replayable and durable intent-log chain, or a future receipt authority
that explicitly proves equivalent recovery behavior.

`fsync` must not return success merely because:

- writeback was queued;
- page-cache pages were marked clean before the storage/replay boundary;
- the intent log contains a marker that is not sufficient to redo the bytes;
- a best-effort background commit is expected to run later.

If writeback fails, `fsync` must return an error or retain the error so a later
barrier reports it according to the VFS contract.

### Relative to the intent log

Intent-log records establish replay ordering. Page-cache writeback must obey
these rules:

- A dirty byte range acknowledged as recoverable must have either durable data
  in storage or a replayable intent record that contains or identifies the
  bytes strongly enough for recovery.
- `Flush`, `Fsync`, and `WriteIntentAck` records are barrier or acknowledgment
  evidence. They do not replace the content write, metadata publication, or
  clean transition.
- `TxBegin`, `TxCommit`, and `TxAbort` define group boundaries. `TxCommit`
  must not become the durable authority for a group until the group's dirty
  byte ranges are either written back or replayable. `TxAbort` must not leave
  dirty page-cache bytes visible as clean committed data.
- If an intent-log append, flush, or checkpoint fails, the affected page range
  must remain dirty, be retried, or surface an error. It must not become clean.

### Relative to crash recovery

After a crash, in-memory page-cache state is gone. Recovery authority is the
newest valid committed root plus durable intent-log replay. For any byte range
that was dirty before the crash, recovery may expose only one of these states:

- the bytes are present through the selected committed root;
- the bytes are replayed from durable intent-log records;
- the bytes are absent because no completed barrier promised durability.

Recovery must not rely on a pre-crash clean bit, writeback-pending bit, or
background queue entry. If recovery cannot prove the bytes through committed
storage or replay, it must classify the gap rather than present an
unsubstantiated durability claim.

## Boundary With `tidefs-cache-coherency`

`tidefs-cache-coherency` owns invalidation event delivery and subscriber
boundaries for lease revocation, inode invalidation, range invalidation, and
full-cache invalidation. Its current subscriber contract allows clean,
unpinned entries to be invalidated and explicitly preserves dirty and
writeback pages.

This writeback authority owns the dirty/writeback side of that boundary:

- Invalidation may remove stale clean cache.
- Invalidation may fence dirty or writeback ranges and require drain/retry.
- Invalidation must not decide that dirty bytes are durable.
- Invalidation completion for destructive operations must wait for the
  writeback authority or return a classified error.

Issue #443 (closed) provided the focused-unit cache-coherency proof for
dirty -> writeback -> clean lifecycle, invalidation fencing, and crash-recovery
integration.

## Boundary With `tidefs-intent-log`

`tidefs-intent-log` owns record encoding, frame checksums, segment scanning,
record sequence, transaction markers, and replay dispatch. Current records
include buffered writes, flush markers, fsync markers, write-intent
acknowledgments, and transaction begin/commit/abort markers.

This writeback authority owns how page-cache state consumes that log:

- dirty pages must identify the intent-log coverage required for recovery;
- writeback completion must join content/metadata persistence with the
  relevant log ordering;
- replay markers must not be treated as clean-page authority unless the bytes
  are also durable or replayable;
- replay idempotency must be proven before the claim path can validate crash
  behavior.

Issue #445 (closed) provided the focused-unit intent-log replay idempotency
proof under repeated replay and crash during replay.

## Follow-Up Implementation Map

The implementation work is intentionally split so each follow-up can own a
non-overlapping write set. The rows marked "create after #1065" are design
outputs from this decision; they should become GitHub issues after this design
lands, before implementation starts.

| Issue | Slice | Primary write set | Boundary |
|---|---|---|---|
| #1532 | Dirty-page lifecycle unification. | `crates/tidefs-cache-core/src/page_cache.rs`, `crates/tidefs-cache-core/tests/`, `crates/tidefs-local-filesystem/src/dirty_page_tracker.rs`, `writeback.rs`, `writeback_daemon.rs`, `page_cache/`, and focused local/cache tests. | Owns dirty/writeback/clean state and duplicate dirty-index reconciliation. Does not edit FUSE adapter policy, kmod address-space callbacks, lease transport, or intent-log schema. |
| create after #1065 | Local fsync/fdatasync and recovery ordering. | `crates/tidefs-local-filesystem/src/fuse_fsync.rs`, `lib.rs` sync paths, `commit_group.rs`, `intent_log.rs`, `recovery.rs`, `crash_recovery.rs`, `txg_replay.rs`, and focused local runtime/unit tests. | Owns local recovery-safe barrier semantics and LOG_DEVICE/import ordering. Does not change adapter cache invalidation, kmod callbacks, or cluster leases. Must coordinate with #842 for receipt emission rather than duplicate receipt policy. |
| create after #1065 | FUSE writeback-cache projection. | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs`, `fsync_handler.rs`, `mmap_coherency.rs`, FUSE writeback/read cache tests, and focused FUSE validation artifacts. | Consumes local durability authority. Does not own durable inode lookup/forget (#665/#709), FUSE invalidation fences (#752), or cluster lease transport. |
| create after #1065 | Kernel mmap/writeback projection. | `kmod/`, `crates/tidefs-kmod-posix-vfs/`, kernel address-space/writeback/fsync/mmap validation hooks, and focused kernel validation artifacts. | Consumes local/kernel storage authority. Does not change FUSE adapter policy, userspace local-fs dirty accounting, or clustered invalidation feed. |
| create after #1065 | Claim-gate and no-hidden-writeback evidence. | `validation/`, `validation/claims.toml`, `docs/CLAIM_REGISTRY.md`, `xtask/`, and evidence manifests. | Records evidence only after runtime implementation exists. Does not implement writeback, recovery, FUSE, kmod, or lease behavior. |
| #752 | FUSE data-cache invalidation and generation fences. | `apps/tidefs-posix-filesystem-adapter-daemon/src/` data-cache, notification, mmap-coherency, and adapter tests only. | Existing invalidation implementation slice. Does not edit durable lookup/forget ownership or writeback durability policy. |
| #753 | Kernel page-cache coherency notifications and stale-generation checks. | `kmod/`, `crates/tidefs-kmod-posix-vfs/`, kernel-facing validation hooks, and focused kernel cache tests. | Existing kernel invalidation slice; closed evidence remains bounded to invalidation/fencing and does not close writeback durability. |
| #754 | Clustered cache lease and epoch invalidation plumbing. | `crates/tidefs-cache-coherency/`, `crates/tidefs-lease/`, `crates/tidefs-lease-manager/`, `crates/tidefs-membership-epoch/`, `crates/tidefs-transport/`, and focused lease/transport tests as needed. | Existing cluster invalidation slice; closed evidence remains bounded to invalidation messages and wait policy, not runtime dirty durability. |

## Claim Path Gates

`local.vfs.page_cache_writeback_authority.v1` may move from authority path to
validated claim only when evidence shows:

- every dirty lifecycle transition is observable in the relevant runtime path;
- writeback triggers cover memory pressure, `fsync`/`fdatasync`/`syncfs`,
  commit-group close, and explicit flush;
- `tidefs-cache-coherency` invalidation proves dirty/writeback preservation and
  bounded drain/error behavior;
- `tidefs-intent-log` replay proves idempotent repeated application and crash
  during replay;
- runtime crash evidence covers write -> fsync -> read -> crash/recover for the
  local VFS path;
- no-hidden-queue evidence accounts for dirty bytes, writeback work, and
  retries.

Until those gates are met, this document is the current authority vocabulary
and ordering target only. It is not production durability evidence.

## Related Work

- TFR-008 in `docs/REVIEW_TODO_REGISTER.md`: tracks the broader recovery,
  fsync, writeback, mmap, and page-cache authority gap.
- `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`: defines the invalidation
  trigger surface, stale-generation rule, and FUSE/kernel/cluster coherency
  lease model.
- GitHub issue #443 (closed): cache-coherency proof for writeback lifecycle,
  invalidation, and crash integration. Evidence consumed by this authority
  document.
- GitHub issue #445 (closed): intent-log replay idempotency under crash
  injection. Evidence consumed by this authority document.
- GitHub issue #486 (closed): local VFS write/fsync/read crash-recover runtime
  evidence. Bounded to OpFsyncBeforeFlush; consumed by
  `local.vfs.write_fsync_crash.v1`.
- `validation/claims.toml`: `local.vfs.page_cache_writeback_authority.v1` is
  registered as blocked; mounted writeback, mmap, and no-hidden-queue runtime
  evidence remain required before the claim can validate.
- GitHub issue #1065: records this integrated survey, authority-model
  comparison, chosen boundary, non-claims, and follow-up implementation map.
