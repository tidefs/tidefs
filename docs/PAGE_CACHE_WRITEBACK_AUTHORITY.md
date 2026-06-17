# Page Cache Writeback Authority

Maturity: current authority document for TFR-008 and GitHub issue #511.

Authority claim path: `local.vfs.page_cache_writeback_authority.v1`.

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
- TFR-008 remains open. Issue #443 owns the cache-coherency/writeback proof
  slice, issue #445 owns intent-log replay idempotency, and runtime
  write/fsync/read/crash-recover evidence remains separate from this document.

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

Issue #443 is the related implementation/proof slice for dirty -> writeback ->
clean lifecycle, invalidation fencing, and crash-recovery integration.

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

Issue #445 is the related implementation/proof slice for intent-log replay
idempotency under repeated replay and crash during replay.

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
- GitHub issue #443: cache-coherency proof for writeback lifecycle,
  invalidation, and crash integration.
- GitHub issue #445: intent-log replay idempotency under crash injection.
- `validation/claims.toml`: current crash-safety claims remain blocked until
  runtime evidence exists.
