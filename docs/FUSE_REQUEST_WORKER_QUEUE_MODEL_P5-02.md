# fuse request worker and queue model (v0.314)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document settles `P5-02` at production depth.

It is the source-of-truth for the live userspace **posix_filesystem_adapter** runtime on Linux 7.0:
- request classes
- queue families
- worker pools
- ingress / egress ownership
- backpressure
- interrupt / forget handling
- reply commit law
- memory-domain placement
- and the explicit seam to later kernel implementations

See also:
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md`
- `docs/MEMORY_PRESSURE_RECLAIM_RESERVE_INTERACTION_P4-03.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Scope and non-goals

This pass defines the **worker/queue/runtime law** for the userspace FUSE path.
It does **not** settle the final page-cache / mmap / writeback contract in full; that remains `P5-03`.

The point of this pass is to make the runtime topology implementable without later discovering that:
- queue ownership was ambiguous,
- interrupts / forgets had no lawful fast path,
- request classes mixed incompatible blocking behavior,
- or adapter-local backpressure quietly became sovereignty.

## 2. Runtime topology

One mounted posix_filesystem_adapter session is one `PosixFilesystemAdapterSessionRuntimeRecord` with these long-lived components:

1. **session supervisor**
   - mount bootstrap
   - INIT negotiation handoff
   - feature/floor selection
   - teardown / crash accounting

2. **ingress reader set**
   - blocking `readv()` on `/dev/fuse`
   - decodes wire headers
   - freezes the minimal projection context mirror
   - classifies requests into queue families

3. **worker lanes**
   - class-specific pools with bounded concurrency
   - each lane owns only request classes with compatible blocking and ordering law

4. **reply commit lanes**
   - separate from ingress
   - commit small replies and bulk data replies under reply-byte credits
   - maintain no hidden truth; they only serialize already-decided results

5. **maintenance lane**
   - forget drains
   - release finalizers
   - session stop / drain

6. **interrupt router**
   - maps FUSE `INTERRUPT` to in-flight request cancellation tokens
   - never performs semantic work itself

## 3. Session phases

### 3.1 Bootstrap phase

Before steady-state workers are live, the session runs in a narrow bootstrap phase:
- mount open
- initial `/dev/fuse` negotiation
- `INIT` handling
- worker-pool sizing
- queue/shard creation
- backpressure reserve initialization

Only after `INIT` completes successfully may steady-state lanes accept normal traffic.

### 3.2 Steady-state phase

In steady-state, posix_filesystem_adapter runs as a **classified multipool**.
The canonical topology is:

- **1 supervisor**
- **R ingress readers**
- **1 urgent-control worker**
- **M metadata workers**
- **N namespace-mutation workers**
- **D directory-stream workers**
- **W writeback/data-mutation workers**
- **L blocking-lock workers**
- **1..2 maintenance workers**
- **1 small-reply committer + 1..2 bulk-reply committers**

### 3.3 Sizing law

Default runtime sizing for Linux 7.0 userspace:

- `R = clamp(cpu_count / 2, 1, 4)`
- `M = clamp(cpu_count, 2, 8)`
- `N = clamp(cpu_count / 2, 2, 8)`
- `D = clamp(cpu_count / 4, 1, 4)`
- `W = clamp(cpu_count / 2, 2, 8)`
- `L = clamp(cpu_count / 4, 1, 4)`
- `reply.small = 1`
- `reply.bulk = clamp(cpu_count / 4, 1, 2)`

These are **policy defaults**, not hard ABI.
They are exposed through `control_plane`, not environment folklore.

## 4. Queue families

The steady-state queue model has **8 canonical request classes** and **2 reply classes**.

### 4.1 Request classes

| Class | Scope | Ordering law | Blocking law | Notes |
|---|---|---|---|---|
| `queue_class_0.control_urgent` | `INIT`, `DESTROY`, `INTERRUPT`, `FORGET`, `BATCH_FORGET` | session-order where required | may not block on product/runtime work | reserved control path |
| `queue_class_1.meta_read` | `LOOKUP`, `GETATTR`, `ACCESS`, `READLINK`, small metadata reads | shard-order only | non-blocking except brief policy_authority calls | hottest small-op lane |
| `queue_class_2.namespace_mut` | create/unlink/rename/link/symlink/mknod/xattr mutation | parent-scope / dual-parent ordered | may wait on publication but not on lock waits | one mutator per shard |
| `queue_class_3.dir_stream` | `OPENDIR`, `READDIR`, `READDIRPLUS`, `RELEASEDIR`, `FSYNCDIR` | dir-handle order | non-blocking except reply commit | cookie law stays local to dir stream |
| `queue_class_4.file_read` | `OPEN`, `READ`, `LSEEK`, small ioctls/poll that do not block long | handle/object order where needed | no long lock waits | bulk-read reply path attaches here |
| `queue_class_5.file_writeback` | `WRITE`, `SETATTR`, `FALLOCATE`, `COPY_FILE_RANGE`, `FLUSH`, `FSYNC`, `RELEASE` | object/dirty_writeback_0 order | may block on writeback/publication | owns dirty-window state |
| `queue_class_6.lock_wait` | `GETLK`, `SETLK`, `SETLKW`, `FLOCK` | lock-key order | explicitly blocking and cancelable | only lane that may park on lock waits |

### 4.2 Reply classes

| Class | Payload kind | Commit path | Notes |
|---|---|---|---|
| `reply_class_0.small_reply` | metadata / errno / short buffers | single committer | minimizes lock contention and preserves urgent responsiveness |
| `reply_class_1.bulk_reply` | large `READ`, `READDIRPLUS`, large xattr buffers | one or two committers under reply-byte credits | keeps read workers from blocking on long kernel copies |

## 5. Sharding law

The worker pools do **not** run against one global FIFO.
They shard by the smallest lawful scope that preserves correctness.

### 5.1 Canonical shard keys

- `secret_key_policy_0.session` — session-global control/maintenance
- `secret_key_policy_1.parent_dir` — parent-directory namespace mutations
- `secret_key_policy_2.dual_parent_pair` — rename-style two-parent mutations, ordered by canonical parent tuple
- `secret_key_policy_3.object_read` — stable object/inode read locality
- `secret_key_policy_4.object_write` — stable object/inode dirty/writeback locality
- `secret_key_policy_5.dir_handle` — directory stream locality
- `secret_key_policy_6.lock_scope` — file/record lock scope

### 5.2 Ordering law

- namespace mutations must serialize per parent or dual-parent tuple
- file writeback mutations must serialize per object dirty-window scope
- blocking lock waits must not occupy non-lock workers
- forget drains may bypass heavy lanes but must still preserve reference-drop order per subject where required

## 6. Request lifecycle

### 6.1 Ingress freeze

Each ingress reader:
1. acquires a `FuseIngressFrame` from `memory_domain_3.adapter_serving_hot`
2. performs wire decode
3. emits `PosixFilesystemAdapterRequestContextMirrorRecord`
4. classifies the request to one queue class
5. binds a shard key
6. performs admission against `PosixFilesystemAdapterBackpressureStateRecord`
7. enqueues work or returns an early throttling/error reply

### 6.2 Worker execution

Each worker lane:
2. maps the request through the `posix_filesystem_adapter` adapter packet law (`W8-05`)
3. emits one or more canonical policy_authority requests where required
4. receives a canonical response envelope / schema_codec receipts
5. prepares a `PosixFilesystemAdapterReplyCommitRecord`
6. hands it to `reply_class_0` or `reply_class_1`

### 6.3 Reply commit

Reply committers:
- own the final `writev()` to `/dev/fuse`
- account `reply_bytes_inflight`
- release frame/payload loans only after successful kernel acceptance or terminal session teardown

Workers may not bypass this path except in the bootstrap `INIT` phase.

## 7. Memory ownership and buffer law

### 7.1 Ingress buffers

Ingress frames are borrowed from `memory_domain_3.adapter_serving_hot` and remain valid until either:
- the request is converted into a staging/dirty structure, or
- the reply is committed / request is forgotten.

### 7.2 Write payloads

Write payload bytes begin life as ingress-frame slices.
They become authoritative mutation input only after being copied or loaned into:
- `memory_domain_2.staging_dirty` for dirty-window formation, or
- a future page-loan path defined by `P4-04` / `P5-03`.

### 7.3 Read reply payloads

Large read replies allocate from `memory_domain_3.adapter_serving_hot` or a future zero-copy path.
Bulk replies consume `reply.bulk` credits so read workers do not become implicit copy threads.

### 7.4 Forget / interrupt tokens

Forget and interrupt state uses tiny control-domain objects only:
- no large payload allocations
- no product cache admission

## 8. Backpressure law

`PosixFilesystemAdapterBackpressureStateRecord` tracks at least these bounded counters:

- `inflight_request_count`
- `inflight_request_bytes`
- `reply_bytes_inflight`
- `dirty_window_bytes`
- `bulk_read_reply_bytes`
- `lock_wait_count`
- `maintenance_backlog`

### 8.1 Reserved control capacity

`queue_class_0.control_urgent` always has a reserved floor.
Heavy read/write traffic may not starve:
- `INTERRUPT`
- `FORGET`
- `DESTROY`
- teardown drain work

### 8.2 Pressure response

Under memory pressure (`P4-03`):
- `queue_class_4.file_read` and `queue_class_5.file_writeback` are throttled first by byte credits
- `queue_class_6.lock_wait` is capped by count, not bytes
- `queue_class_0.control_urgent` remains serviced
- `queue_class_7.maintenance` is allowed enough runway to free frames, complete forgets, and drain releases

## 9. Interrupt / forget / blocking law

### 9.1 Interrupts

`INTERRUPT` is handled in `queue_class_0.control_urgent`.
It resolves a `PosixFilesystemAdapterInterruptTokenRecord` and marks the target request as cancel-pending.

Only request classes that can lawfully block consult cancel tokens:
- `queue_class_6.lock_wait`
- selected `queue_class_5.file_writeback` operations waiting on publication fences

### 9.2 Forgets

`FORGET` and `BATCH_FORGET` never enter the heavy worker lanes.
They go either:
- inline to the urgent control path, or
- into a tiny `PosixFilesystemAdapterForgetBatchMirrorRecord` queue drained by maintenance.

The design rule is explicit:
- forgets may not be starved behind bulk I/O
- but they also may not mutate hidden authority directly; they only release projection/runtime references

### 9.3 Blocking lock waits

`SETLKW`/blocking flock live only in `queue_class_6.lock_wait`.
That lane is:
- bounded by count
- cancel-aware
- isolated from read/writeback throughput

## 10. Worker classes to future kernel mapping

This userspace queue law is also the preparation for future kernel variants.
The mapping is:

- `queue_class_0.control_urgent` -> kernel control workqueue
- `queue_class_1.meta_read` / `queue_class_3.dir_stream` -> VFS-facing fast metadata workers
- `queue_class_2.namespace_mut` -> ordered namespace workqueue
- `queue_class_4.file_read` / `queue_class_5.file_writeback` -> page-cache / writeback / block completion workqueues
- `queue_class_6.lock_wait` -> sleeping lock wait path
- `queue_class_7.maintenance` -> background drain / finalizer workqueue

The future kmod may change the mechanics (`workqueue`, `RCU`, page-cache hooks), but it may not change the semantic queue classes without revisiting this law.

## 11. Rust crate / module decomposition

The runtime is now prepared to land in these userspace crate/module families:

- `tidefs-posix_filesystem_adapter-workers-io`
- `tidefs-posix_filesystem_adapter-workers-locks`
- `tidefs-posix_filesystem_adapter-reply`
- `tidefs-posix_filesystem_adapter-runtime`
- `apps/tidefs-posix-filesystem-adapter-daemon`

These are **seam families**, not a promise of one-crate-per-row.
The point is that ingress, scheduling, workers, reply commit, and maintenance are no longer allowed to blur into one daemon blob.

## 12. Acceptance checklist for this design item

`P5-02` counts as production-settled only because all of the following are now explicit:
- request classes
- reply classes
- shard keys
- worker pool sizing law
- ingress / worker / reply ownership
- interrupt / forget fast-path law
- backpressure counters and reserved urgent capacity
- relationship to memory domains and future kernel workqueues

Open work intentionally left to later items:
- `P5-03` page-cache / writeback / mmap integration detail
- `P4-04` zero-copy / DMA / page-loan law
- `P7-03` kernel locking / RCU / pinning / workqueue mechanics
