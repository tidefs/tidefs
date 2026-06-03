# Kernel Resident Pool Engine Architecture

This document is the implementation authority for the Linux 7.0 kernel-resident
TideFS runtime. It connects the POSIX VFS module, block-volume module, imported
physical block devices, transaction/replay state, and kernel execution contexts
into one design.

It consumes:

- `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md`
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`
- `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md`
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`
- `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`
- `crates/tidefs-kmod-posix-vfs/README.md`
- `crates/tidefs-block-kmod/README.md`

## Current Release Interpretation

Read this document with `docs/REVIEW_TODO_REGISTER.md` and

- `#6219` proved a Linux 7.0 block-kmod bring-up data path in QEMU. That is
- `#6225` proved partial POSIX VFS default-mount behavior and committed-root
  namespace/data readback still uses a fixed bring-up table.
- `#6252` is the current root gate for replacing that table with committed-root
  import and canonical object/extent/inode/intent replay.
- `#6253`, `#6254`, and `#6191` depend on that replay path before full-kernel
  no-daemon closure can be claimed.

No source-only, cargo-only, mock, fixed-table-only, or shim-local-storage path
can close this architecture.

## Core Decision

TideFS kernel mode has one pool/engine core per imported pool. The POSIX VFS
module and the block-volume module are front-ends over that core.

They are not separate stores, not separate transaction authorities, and not
daemon-backed escape paths.

```text
physical block devices
  -> KernelDeviceSet
  -> KernelPoolCore
       - label/import state
       - committed-root / replay cursor
       - allocation and object layout
       - txg / intent / flush authority
       - capacity and statfs counters
       - lock, pin, and worker registries
  -> POSIX VFS front-end       (mount -t tidefs)
  -> block-volume front-end    (/dev/tidefsN exports)
```

The kernel pool core is the only in-kernel authority for mounted filesystem
state, exported block-volume state, writeback, recovery, placement, reserve,
and admission. Userspace tools may configure and inspect through declared
kernel UAPI. They may not be required as always-running support daemons.

## Current Implementation Tier

The current `tidefs_posix_vfs.ko` integration tier is intentionally narrow but
is no longer bootstrap-only:

- `mount -o bootstrap -t tidefs none <mountpoint>` is a development proof only;
- the bootstrap mount allocates in-kernel mount state, root inode, `statfs`,
  and `kill_sb` teardown, then proves those in Linux 7.0 QEMU;
- default `mount -t tidefs /dev/<pool-device> <mountpoint>` reads the pool
  label from the lower block device, creates an engine-backed superblock, and
  stores a mounted `KernelPoolCore` context in `s_fs_info`;
- the first engine-backed operation slice keeps a small fixed in-kernel
  namespace/data table in the pool data region so Linux 7.0 QEMU can prove
  no-daemon create, write, read, mkdir, readdir, sync, remount readback,
  unlink, rmdir, clean unmount, and module unload;
- the mounted mutation path also republishes committed-root state after
  successful state/data writes. VCRL remains the current mount-selection
  ledger; new pool images reserve four system-area blocks so the same
  publication also writes duplicate VCRP pointer records and the canonical
  VRBT committed-root block. Older one-block VCRL images remain mountable and
  skip VRBT/VCRP publication with an explicit warning;
- this table is deliberately a bring-up mirror. It is not the final
  object/extent/intent-log engine, not page-cache/writeback, not xfstests, not
  must replace table readback with object/extent state rebuilt from committed
  roots plus replayable intent records, or record the exact primitive that
  blocks that replacement.

Workers may use the bootstrap path to test Linux VFS mechanics. They must not
close engine-backed, storage-backed, or full-kernel issues with bootstrap-only
the specific mounted operations it exercises; higher tiers still require the

## Kernel Pool Core

`KernelPoolCore` is the conceptual owner for one imported TideFS pool in kernel
space. The implementation may split this across Rust and small C shims where
Linux 7.0 Rust wrappers are missing, but the ownership boundary stays the same.

Required state:

- pool identity: pool UUID, generation, feature set, import mode;
- physical devices: opened lower block devices with queue geometry, sector
  size, label locations, system-area offsets, and failure state;
- committed-root state: selected committed root, transaction group, replay
  cursor, intent-log frontier, checkpoint/snapshot frontier;
- object/layout state: object locator, extent map, capacity/reserve counters,
  allocation cursors, dirty ranges, and segment-cleaner state;
- Linux front-end state: active superblocks, active block exports, open file
  handles, active bios, page-cache windows, direct-I/O pins;
- execution state: workqueues, delayed work, optional kthreads, timers, stop
  flags, freeze/quiesce fences, and teardown receipts.

The core must be reference counted by active front-ends. A pool cannot be
destroyed or exported while a mounted superblock, open file, active block
export, pinned folio, queued bio, or worker item still holds a reference.

## Physical Block Devices

Physical member devices are imported by the kernel pool core. They are not
exposed to the POSIX VFS front-end as files, and they are not represented by the
TideFS block export front-end.

Import sequence:

1. Open each declared lower Linux block device through the Linux block-device
   API available in the Linux 7.0 tree. The exact C/Rust symbol is a build-time
   API fact and must be verified in Kbuild, not guessed in docs.
3. Group devices by pool UUID and topology generation.
   and system-area bounds.
5. Read the committed-root ledger from the system area.
6. Select the newest valid committed root.
7. Replay only the permitted intent records for the selected recovery mode.
8. Publish `KernelPoolCore` only after the root, replay cursor, and capacity
   counters are internally consistent.

Lower-device I/O must be submitted through kernel block-layer APIs. If Rust
wrappers are missing in Linux 7.0, a small C shim may own the unsafe `bio` /
`struct block_device` mechanics and export a narrow ABI to Rust. That shim may
not contain TideFS policy, allocation, transaction, or recovery logic.

## POSIX VFS Front-End

The POSIX VFS module owns Linux VFS objects and delegates filesystem semantics
to `KernelPoolCore`.

Mount:

- parse mount source/options into a device set or an already imported pool id;
- call pool import/attach;
- construct `super_block` state from the committed root;
- store the pool/mount context in `s_fs_info`;
- create the root inode/dentry from the committed root;
- attach operation tables only for operations whose backing engine path is
- fail unsupported operations with explicit Linux errnos.

VFS callbacks:

- lookup/getattr/readdir/read-only clean-read paths may use RCU mirrors and
  short synchronous engine calls where sleepability allows;
- create/link/unlink/rename/mkdir/rmdir/symlink/mknod/tmpfile must enter the
  transaction and intent-log path before visible mutation;
- write, mmap writeback, fsync, syncfs, and direct I/O must share one dirty
  epoch and transaction-sync path;
- `statfs` must come from pool capacity counters, not fixed placeholder data;
- `kill_sb` must close ingress, drain writeback/pins/work items, drop active
  inodes, release the pool reference, and then release lower devices if this
  was the last front-end reference.

The Linux page cache is the POSIX page cache in kernel mode. TideFS may keep
metadata/object mirrors, but it must not create a second authoritative data
cache that can diverge from the Linux page cache.

## Block-Volume Front-End

The block module exports TideFS logical volumes as Linux block devices. It does
not import the physical member devices and it does not own a separate store.

```text
Linux block layer queue_rq
  -> tidefs-block-kmod
  -> KernelPoolCore logical-volume I/O
  -> object/layout/txg engine
  -> physical member block devices
```

Rules:

- `queue_rq` is the real Linux 7.0 entry point. Do not design around a Rust
  `submit_bio` callback that the tree does not expose.
- Read/write/flush/discard map to `KernelPoolCore` logical-volume operations.
- FUA and flush must force the same durable ordering used by POSIX `fsync` and
  `syncfs`.
- Discard must update logical extents and allocation/reclaim state through the
  transaction path. It may not silently zero a side buffer in production mode.
- Queue limits come from the logical volume and pool geometry.
- The in-memory `BlockExport` backend is bring-up/testing only. It is not

The block export may be used by other filesystems as a normal Linux block
device, but it must not be used as a member device for the same TideFS pool.
Self-stacking a TideFS exported block device underneath its own pool is a
configuration error and must fail before activation.

## Shared VFS/Block Interaction

When POSIX VFS and block exports are active on the same pool, they share:

- one transaction group state machine;
- one committed-root publication path;
- one capacity/reserve model;
- one intent/replay frontier;
- one allocator and object locator;
- one lock/range broker;
- one pin/drain broker;
- one worker registry;
- one teardown/quiesce protocol.

Consequences:

- `fsync`, `syncfs`, block `REQ_OP_FLUSH`, and block FUA all converge on the
  same txg sync machinery.
- POSIX dirty folios and block dirty ranges must be ordered by transaction
  generation before publication.
- `statfs` and block capacity/queue-limit reports must derive from the same
  pool geometry and reserve state.
- Snapshot/checkpoint/cutover operations must fence both VFS and block
  front-ends before publishing or rolling back.
- A block export cannot bypass POSIX namespace policy when it addresses a
  volume object; the exported volume is an admitted object with its own
  capability/lease state.
  pin epoch machinery before truncate, discard, relocate, failover, or unmount.

## Execution Contexts

No ad hoc kernel thread is allowed. Every execution context must be declared,
owned by `KernelPoolCore` or the module global registry, stopped on teardown,
and classified by P7-03.

### Synchronous Callback Contexts

These run in Linux VFS or block-layer caller context and must finish promptly:

- VFS lookup/getattr/open/read/readdir where the backing mirror is ready;
- VFS mutation admission and short engine operations;
- address-space dirty marking and page-cache state transitions;
- blk-mq `queue_rq` request classification and bounded dispatch;
- statfs, ioctl, queue-limit queries, and cheap observe reads.

Synchronous callbacks may sleep only when the Linux callback permits sleeping.
They may not hold spinlocks or RCU read sections across allocation, lower block
I/O, txg sync, policy waits, or worker drain.

### Workqueue Families

The canonical workqueue families from P7-03 are binding:

| Family | Kernel Pool Use |
|---|---|
| `ControlSerial` | mount/import/export, freeze/thaw, cutover, emergency state transitions |
| `NamespaceMut` | create/unlink/rename/mkdir/rmdir/symlink/mknod continuations by object/range key |
| `PageWriteback` | dirty-folio sealing, writepage/writepages, fsync continuations, mmap writeback completion |
| `BlockSubmitComplete` | lower-device bio submission/completion and block-export continuations |
| `ReclaimRelocate` | cleanup queues, segment cleaning, relocation, rebuild, scrub repair |
| `EmergencyRecovery` | protected reserve recovery, read-only flip, abort, failover stop tickets |

Workqueues are mechanics. They do not own policy, reserve truth, publication
truth, or recovery truth.

### Kthreads And Timers

Use delayed work when a periodic task can be expressed as bounded ticks. Use a
dedicated kthread only for a long-lived pool service that must wait, be woken by
multiple event classes, and carry explicit stop/drain semantics.

Allowed dedicated services:

- `tidefs-txg/<pool>`: required once writes are admitted. Wakes on dirty bytes,
  time threshold, fsync/syncfs/flush/FUA demand, freeze, or shutdown. Publishes
  committed roots and advances replay cursors.
- `tidefs-rebuild/<pool>`: present only when degraded/rebuild/backfill work is
  active. Uses bounded credits and can be absent on healthy single-node pools.
- `tidefs-transport/<pool-or-session>`: future kernel transport/session service
  only after the transport design reaches kernel residency. It is not part of
  the first POSIX VFS or block export closure.

Preferred delayed-work services:

- cleanup/reclaim tick;
- scrub/verify tick;
- pressure monitor tick;
- retry/backoff for transient lower-device errors.

Every service must have:

- a declared workqueue or kthread class;
- a stop flag;
- a drain completion;
- a maximum outstanding work budget;
- memory reserve accounting;
- no dependency on usermode helpers for normal operation.

## Locking, Pins, And Reclaim

The P7-03 lock order is binding:

`PolicyRwsem -> DomainMutex -> RangeRwsem -> PinMutex -> ObjectSpin -> SeqCountEpoch/RcuAnchor`

Operational rules:

  against generation before returning Linux-visible state.
- Mutations acquire range locks before intent/txg admission.
- Page-cache folios, bio vectors, direct-I/O pages, and DMA mappings all create
  pin obligations.
- Pins debit reserve and must be associated with a pin epoch.
- Truncate, hole punch, discard, relocation, failover, and unmount must fence
  and drain relevant pin epochs before freeing or reusing storage.
- Memory allocation in writeback/reclaim paths must use reserve-aware GFP
  choices and must not recurse into filesystem reclaim while holding object
  spinlocks or RCU read sections.

## Recovery And Replay

Mount-time recovery is a kernel pool-core responsibility:

- select newest valid committed root;
- replay only records that are valid for the chosen recovery mode;
- refuse read-only opens that would require mutating replay unless the mode
  explicitly permits recovery writes;
- publish the root only after replay and capacity counters agree;

Write-path durability:

- POSIX mutation and block write admission records intent before exposing
  success when durability requires it;
- data writeback and metadata publication are ordered by transaction group;
- `fsync`, `syncfs`, block flush, and FUA wait for the relevant transaction
  boundary;
  not only module load or mount success.



| Tier | What It Proves | What It Does Not Prove |
|---|---|---|
| Kbuild | `.ko` builds against Linux 7.0 | runtime behavior |
| QEMU module load | module loads/unloads in Linux 7.0 | mount, I/O, no-daemon |
| bootstrap mounted VFS | `-o bootstrap` root/statfs/teardown path | storage, read/write, xfstests, full-kernel |
| engine mounted VFS | imported pool, committed root, real root inode, statfs, at least one VFS operation | block export, crash consistency |
| kernel block I/O | registered block device and real read/write/flush/discard through `queue_rq` | POSIX VFS correctness |
| crash/remount | committed-root and replay-cursor survive forced shutdown | performance or full soak |
| full-kernel no-daemon | VFS/block/recovery/writeback operate with no required support daemons | optional operator/query tooling absence |

No issue may close a higher tier with a lower-tier artifact.

## Implementation Order

1. Keep the bootstrap POSIX mount option as a VFS mechanics proof.
2. Build `KernelPoolCore` skeleton with lower-device import, label read,
   committed-root selection, refcounting, and teardown.
3. Replace bootstrap mount with engine mount for a read-only root.
4. Wire `statfs`, lookup, getattr, readdir, open, read, and readahead from the
   committed root.
5. Add write admission, intent records, txg sync service, fsync/syncfs, and
   page-writeback integration.
6. Wire block-kmod `queue_rq` to logical-volume operations on the same pool
   core.
7. Add crash/remount and no-daemon residency gates.
8. Add multi-device degrade/rebuild/scrub/relocate workers.
9. Only after both client front-ends are proven, evaluate selected-domain
   kernel policy authority.

This order is mandatory unless an issue explicitly documents a stronger
dependency proof.
