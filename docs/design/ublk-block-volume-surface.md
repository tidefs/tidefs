# ublk Block Volume Surface: Volume Model, Control/Data Plane, Export Locks, Volume Index

**Issue**: [#1216](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1216)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Layer**: 11 (Export)
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8-11)

**Related**: #1213 (VFS Engine), #1251 (canonical trace), #1233 (FUSE daemon), #1235 (trace emission), #1174 (trace corpus), #1240 (NFS export)

## Abstract

This document defines the ublk block volume surface for tidefs: an upstream Linux
userspace block device (io_uring-based) that exposes tidefs volumes as native
`/dev/ublkb*` devices for VM disks, databases, container storage, and as a block
substrate for other filesystems. The surface obeys the same correctness requirements
propagation — while operating through a dedicated `tidefs-ublk` daemon peer to the
FUSE adapter.

Four existing crates form the current implementation surface: `tidefs-ublk-abi`
(Linux ublk UAPI mirror), `tidefs-block-volume-adapter-core` (deterministic model),
`tidefs-block-volume-adapter-ublk-control-runtime` (io_uring control plane), and
`tidefs-block-volume-adapter-daemon` (daemon binary). This design specifies how
those crates compose with the on-media volume model, the volume index, the VfsEngine
block contract, export locks, and cluster fencing to form a production block export
surface.

---

## 1. Problem Statement

The FUSE filesystem surface is insufficient for workloads that require native block
semantics: VM disk images, database storage engines, container root filesystems,
and as a block substrate for other filesystems (ext4, XFS). These workloads need:

- **Direct block addressing** without FUSE inode/dentry overhead
- **Native discard (UNMAP/TRIM)** for thin provisioning
- **Atomic write-zeroes** for database initialization
- **io_uring-based completion** for low-latency, high-IOPS submission
- **Lease-fenced exclusive RW access** with the same cluster safety as filesystem writes

The ublk (userspace block device) framework in Linux 6.0+ provides the kernel-side
infrastructure. tidefs must provide the userspace daemon, the on-media volume model,
the export lifecycle, and the cluster-coherent data path.

## 2. Scope

### In scope

- **Volume model**: on-media TLV representation, inode semantics, feature flags
- **Volume index**: B+tree keyed by `volume_uuid → inode_id`, admin API backing
- **ublk control plane**: 4-step device lifecycle (ADD_DEV → SET_PARAMS → START_DEV → STOP_DEV/DEL_DEV), queue affinity, resize
- **ublk data plane**: per-queue IO thread loops, io_uring passthrough, read/write/flush/discard/write_zeroes mapping to engine extent ops
- **Export locks**: RW export requires dataset writer lease; lease loss immediately fences block export
- **Dynamic block size mapping**: read/modify/write for misaligned block writes against variable extents
- **VfsEngine block contract**: block-oriented operations on the VfsEngine trait boundary

### Out of scope

- Zoned block device support (UBLK_IO_OP_ZONE_*); deferred to a future design
- NBD/iSCSI block export surfaces; this design covers ublk only
- Block-level encryption at the ublk layer (dataset encryption applies above)
- Multi-path or failover block export (deferred to cluster HA design)
- RDMA data path for block IO (deferred to transport/RDMA design)

## 3. Architecture Overview

```
                          ┌──────────────────────────────┐
                          │    tidefs-ublk daemon        │
                          │                              │
  ┌──────────┐            │  ┌────────────────────────┐  │
  │ Cluster  │◄───────────┤──┤  Export Lock Manager    │  │
  │ Leases   │   lease    │  │  (writer lease monitor) │  │
  │ #1209    │   events   │  └────────────────────────┘  │
  └──────────┘            │                              │
                          │  ┌────────────────────────┐  │
  ┌──────────┐            │  │  Control Plane          │  │
  │Inval Feed│◄───────────┤──┤  (add/set/start/stop/   │  │
  │ #1208    │  inval     │  │   del dev lifecycle)     │  │
  └──────────┘  events    │  └───────────┬────────────┘  │
                          │              │                │
                          │  ┌───────────▼────────────┐  │
                          │  │  ublk IO Threads × N    │  │
                          │  │  (per-queue io_uring    │  │
                          │  │   fetch_req → dispatch  │  │
                          │  │   → commit_and_fetch)   │  │
                          │  └───────────┬────────────┘  │
                          └──────────────┼───────────────┘
                                         │ VfsEngine block ops
                          ┌──────────────▼───────────────┐
                          │  VfsEngine trait boundary    │
                          │  (block_read, block_write,    │
                          │   block_flush, block_discard, │
                          │   block_write_zeroes)         │
                          └──────────────┬───────────────┘
                                         │
                          ┌──────────────▼───────────────┐
                          │  tidefs-local-filesystem      │
                          │  (extent map, commit_group pipeline,   │
                          │   intent log, checksum)       │
                          └──────────────────────────────┘
```

The `tidefs-ublk` daemon is a peer to the FUSE adapter daemon (#1145). Both daemons
implement the same `VfsEngine` trait boundary. The ublk daemon adds:

1. **Control plane**: manages `/dev/ublk*` device nodes via io_uring passthrough to
   `/dev/ublk-control`
2. **Data plane**: per-queue io_uring loops that map block IO commands to VfsEngine
   block operations
3. **Export lock manager**: holds and monitors the dataset writer lease; fences all
   queues on lease loss
4. **Volume index**: resolves `volume_uuid → inode_id` for admin operations

## 4. Volume Model

### 4.1 On-media representation

A volume is a special inode presented as a regular file in the FUSE namespace (so it
can be inspected, snapshotted, copied with `send/recv`, and participates in quota
accounting) but additionally eligible for ublk export.

The inode carries a TLV extension `TLV_VOLUME` (tag value TBD in on-media format
strategy #1218) containing:

```rust
/// On-media TLV_VOLUME payload.
struct VolumeTlvV1 {
    /// Stable volume identity for the lifetime of the volume.
    volume_uuid: [u8; 16],
    /// Logical block size exposed to the block consumer (default 4096).
    logical_block_size: u32,
    /// Physical block size hint for alignment (default = logical_block_size).
    physical_block_size: u32,
    /// Export policy flags.
    export_policy_flags: u32,
}

bitflags! {
    struct VolumeExportPolicyFlags: u32 {
        /// Allow DISCARD (UNMAP/TRIM) operations.
        const ALLOW_DISCARD       = 1 << 0;
        /// Allow WRITE_ZEROES operations.
        const ALLOW_WRITE_ZEROES = 1 << 1;
        /// Require FUA (Force Unit Access) on flush operations.
        const REQUIRE_FUA_ON_FLUSH = 1 << 2;
        /// Volume is read-only (no RW export permitted).
        const READ_ONLY           = 1 << 3;
    }
}
```

### 4.2 Feature flags

Two dataset-level feature flags gate volume functionality:

| Flag | Class | Semantics |
|---|---|---|
| `org.tidefs:volumes` | compat | Volume inodes exist; volume_index may be populated. Older implementations without this flag ignore volumes (they appear as regular files). |
| `org.tidefs:volumes-strict` | ro_compat | Volume invariants enforced strictly. An implementation without this flag mounted read-only may still read volume data but must not export. |

### 4.3 Volume invariants

1. **Block-aligned size**: `inode.size` is always a multiple of `logical_block_size`.
   Setting size to a non-multiple via `truncate(2)` or `fallocate(2)` on the FUSE file
   representation rounds up to the next block boundary.

2. **Exclusive export lock**: While exported read-write via ublk, the volume holds an
   exclusive export lock. No concurrent RW export is permitted. Read-only export may
   be shared.

3. **Zero-on-unwritten**: Reads from unwritten or discarded ranges return zeros.
   This matches the VfsEngine extent semantics where `UNWRITTEN` extents read as zero.

4. **Resize gate**: Volume resize only via an explicit "resize volume" admin operation,
   not through arbitrary `truncate(2)` on the FUSE file representation. This ensures
   the ublk device geometry stays consistent with the on-media extent map during resize
   transitions.

### 4.4 In-memory representation (VfsEngine block contract)

The VfsEngine trait gains block-oriented operations that operate on volume inodes:

```rust
/// VfsEngine block operations — invoked by the ublk data plane.
trait VfsEngineBlock {
    /// Read `block_count` blocks starting at `start_block`.
    fn block_read(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
        start_block: u64,
        block_count: u32,
        buf: &mut [u8],
    ) -> Result<BlockIoResult, VfsError>;

    /// Write `block_count` blocks starting at `start_block`.
    fn block_write(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
        start_block: u64,
        block_count: u32,
        buf: &[u8],
    ) -> Result<BlockIoResult, VfsError>;

    /// Flush all pending writes for this volume through the commit_group commit.
    fn block_flush(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
    ) -> Result<BlockFlushResult, VfsError>;

    /// Discard (punch-hole) a block range.
    fn block_discard(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
        start_block: u64,
        block_count: u32,
    ) -> Result<BlockDiscardResult, VfsError>;

    /// Write zeroes to a block range.
    fn block_write_zeroes(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
        start_block: u64,
        block_count: u32,
    ) -> Result<BlockWriteZeroesResult, VfsError>;

    /// Query volume geometry.
    fn block_get_geometry(
        &self,
        dataset: &DatasetHandle,
        inode: InodeId,
    ) -> Result<BlockVolumeGeometry, VfsError>;
}
```

## 5. Volume Index

### 5.1 Design

A dataset-scoped B+tree `volume_index` keyed by `volume_uuid → inode_id` avoids
namespace scans for admin operations (`LIST_VOLUMES`, `GET_VOLUME_STATUS`) and
export lock lookups. The index is maintained transactionally: every volume create,
delete, or UUID change updates the index within the same commit_group.

```rust
struct VolumeIndex {
    /// B+tree mapping volume_uuid → (inode_id, export_state).
    tree: BPlusTree<[u8; 16], VolumeIndexEntry>,
}

struct VolumeIndexEntry {
    inode_id: u64,
    /// Current export state (if any).
    export_state: Option<VolumeExportState>,
}

struct VolumeExportState {
    /// Node UUID that holds the current export.
    exporter_node: [u8; 16],
    /// Export mode.
    mode: VolumeExportMode,
    /// Epoch at which this export was granted.
    granted_epoch: u64,
}

enum VolumeExportMode {
    ReadOnly,
    ReadWrite,
}
```

### 5.2 Index operations

| Operation | Trigger | Semantics |
|---|---|---|
| Insert | Volume create (mkvol) | Insert `(volume_uuid, inode_id)` with `export_state = None` |
| Delete | Volume destroy | Remove entry; fail if `export_state.is_some()` |
| Acquire export | ublk START_DEV | CAS `export_state` from `None → Some(...)`; requires writer lease |
| Release export | ublk STOP_DEV | CAS `export_state` from `Some(...) → None` |
| Lookup by UUID | Admin GET_VOLUME_STATUS | O(log n) B+tree lookup |
| Scan all | Admin LIST_VOLUMES | B+tree range scan |

### 5.3 On-media layout

The volume index root pointer is stored in the dataset catalog, analogous to the
directory index and orphan index. On mount, the index is opened lazily (only if
`org.tidefs:volumes` is enabled).

## 6. ublk Control Plane

### 6.1 Device lifecycle (4-step)

The `tidefs-block-volume-adapter-ublk-control-runtime` crate already implements the
io_uring control plane for the 4-step device lifecycle. This design formalizes the
integration with the volume model and export locks.

```
                  ┌─────────────┐
                  │   CLOSED    │
                  └──────┬──────┘
                         │ UBLK_CMD_ADD_DEV
                         ▼
                  ┌─────────────┐
                  │   ADDED     │  /dev/ublkc<N> created
                  └──────┬──────┘  queue params negotiated
                         │ UBLK_CMD_SET_PARAMS
                         ▼
                  ┌─────────────┐
                  │  PARAMS_SET │  logical_bs, physical_bs,
                  └──────┬──────┘  max_sectors, discard, dma_align
                         │
            ┌────────────┼────────────┐
            │ acquire export lock     │ ← requires dataset writer lease
            │ populate volume_index   │
            └────────────┼────────────┘
                         │ UBLK_CMD_START_DEV
                         ▼
                  ┌─────────────┐
                  │   ACTIVE    │  /dev/ublkb<N> exposed
                  └──────┬──────┘  IO queues running
                         │
            ┌────────────┼────────────┐
            │ UBLK_CMD_QUIESCE_DEV   │ (optional: drain IO)
            └────────────┼────────────┘
                         │ UBLK_CMD_STOP_DEV
                         ▼
                  ┌─────────────┐
                  │   STOPPED   │  IO queues drained
                  └──────┬──────┘  export lock released
                         │ UBLK_CMD_DEL_DEV
                         ▼
                  ┌─────────────┐
                  │   CLOSED    │  resources freed
                  └─────────────┘
```

### 6.2 Queue affinity

`UBLK_CMD_GET_QUEUE_AFFINITY` pins each IO queue thread to the blk-mq CPU affinity
mask reported by the kernel. This avoids cross-NUMA completion handling and keeps
the IO path cache-warm.

The existing `UblkQueueAffinity` type in `tidefs-ublk-abi` captures the kernel-reported
mask. The daemon spawns one OS thread per queue, sets the CPU affinity, and runs the
IO loop on that thread.

### 6.3 Resize

Volume resize follows the `UBLK_CMD_UPDATE_SIZE` path:

1. Admin operation: `RESIZE_VOLUME(uuid, new_sectors)`
3. Engine extends/truncates the extent map (truncate only if blocks beyond new size are zero/unwritten)
4. Engine commits the commit_group
6. Daemon issues `UBLK_CMD_QUIESCE_DEV` to drain in-flight IO
7. Daemon issues `UBLK_CMD_UPDATE_SIZE` with new device sectors
8. Kernel exposes the new size to block consumers

### 6.4 Features negotiation

At `UBLK_CMD_START_DEV` time, the daemon advertises supported features via
`UblkFeatureFlags`:

| Feature | Always advertised | Conditional |
|---|---|---|
| `SUPPORT_ZERO_COPY` | No (tidefs uses buffered IO via io_uring registered buffers) | — |
| `USER_COPY` | Yes | — |
| `QUIESCE` | Yes | — |
| `ZONED` | No | — |
| `CMD_IOCTL_ENCODE` | Yes | — |
| `NEED_GET_DATA` | Yes | Required for misaligned write RMW |

## 7. Data Plane

### 7.1 IO thread loop

Each queue runs a deterministic loop in `tidefs-block-volume-adapter-ublk-control-runtime`:

```text
loop {
    // 1. Fetch next IO command from the kernel
    io_cmd = io_uring_submit(FETCH_REQ);

    // 2. Decode ublk IO descriptor
    desc = UblkSrvIoDesc::from_sqe(cqe);

    // 3. Map ublk operation to VfsEngine block operation
    match desc.op {
        UBLK_IO_OP_READ       => engine.block_read(...),
        UBLK_IO_OP_WRITE      => engine.block_write(...),
        UBLK_IO_OP_FLUSH      => engine.block_flush(...),
        UBLK_IO_OP_DISCARD    => engine.block_discard(...),
        UBLK_IO_OP_WRITE_ZEROES => engine.block_write_zeroes(...),
    }

    // 4. Commit completion
    io_uring_submit(COMMIT_AND_FETCH_REQ);
}
```

### 7.2 Operation mapping

| ublk op | VfsEngine op | Notes |
|---|---|---|
| `UBLK_IO_OP_READ` | `block_read` | Direct extent read; unwritten extents return zeroes |
| `UBLK_IO_OP_WRITE` | `block_write` | May trigger RMW for misaligned blocks (§9) |
| `UBLK_IO_OP_FLUSH` | `block_flush` | Maps to commit_group sync barrier; FUA writes handled via `UBLK_IO_F_FUA` flag |
| `UBLK_IO_OP_DISCARD` | `block_discard` | Only if `ALLOW_DISCARD` in export policy; maps to punch-hole / UNWRITTEN |
| `UBLK_IO_OP_WRITE_ZEROES` | `block_write_zeroes` | Only if `ALLOW_WRITE_ZEROES`; maps to UNWRITTEN reservation |

### 7.3 Completion semantics

```rust
enum BlockIoCompletion {
    /// IO completed successfully.
    Success,
    /// IO refused: range out of bounds.
    OutOfBounds,
    /// IO refused: misaligned range (start or count not block-aligned).
    Misaligned,
    /// IO refused: operation not supported (e.g., discard on read-only volume).
    Unsupported,
    /// IO refused: export is fenced (lease lost).
    ExportFenced,
    /// IO refused: backpressure (queue depth exceeded).
    Backpressure,
}
```

### 7.4 FUA (Force Unit Access) handling

When the kernel submits a write with `UBLK_IO_F_FUA`, the data plane must ensure
the write reaches stable storage before completing. This is implemented as:

1. Submit `block_write` with `fua = true`
2. Engine writes data + commits a commit_group sync barrier
3. Engine acknowledges only after the commit_group commit completes

### 7.5 Buffer management

The ublk daemon uses io_uring registered buffers (`UBLK_IO_REGISTER_IO_BUF`) for
data transfer. Buffer layout follows the `UblkIoBufferAddress` addressing in
`tidefs-ublk-abi`:

- Each queue gets a dedicated buffer region
- Buffer addresses are computed as `queue_id << QID_OFF | tag << TAG_OFF | offset`
- Total buffer size per queue: `UBLK_IO_BUF_BITS` (32 MiB)

## 8. Export Locks and Cluster Safety

### 8.1 Lease integration

Volume exports are fence-sensitive. The export lock manager integrates with the
cluster lease system (#1209):

- **RW export** requires holding the **dataset writer lease** (exclusive mutation lease
  for the enclosing dataset)
- **RO export** requires holding at least a **dataset reader lease** (shared, non-mutating)
- **No lease** → no export permitted

Lease state is monitored asynchronously:

```rust
struct ExportLockManager {
    /// Current lease handle for the dataset.
    lease: Option<LeaseHandle>,
    /// All active ublk queues (for fencing on lease loss).
    queues: Vec<QueueHandle>,
    /// Whether the export is currently fenced.
    fenced: AtomicBool,
}
```

### 8.2 Fencing on lease loss

When the dataset writer lease is lost (due to network partition, epoch advancement,
or explicit revocation):

1. Lease subsystem delivers `LeaseEvent::Lost` to the export lock manager
2. Export lock manager sets `fenced = true` atomically
3. All in-flight IO in every queue receives `BlockIoCompletion::ExportFenced`
4. New IO from the kernel is refused with `UBLK_IO_RES_ABORT` (−ENODEV)
5. The daemon issues `UBLK_CMD_QUIESCE_DEV` to drain the kernel queue
6. The daemon issues `UBLK_CMD_STOP_DEV` to stop the device
7. Volume index is updated: `export_state → None`
8. The block device is removed from the Linux device namespace

This is the same (term, epoch) fencing mechanism used by filesystem writes (#1209).


filesystem writes. When a commit_group commits on the writer node:

2. Follower nodes that hold a cached block volume receive the event
   in its cache
4. If the follower is a pure reader, it evicts stale cache entries

### 8.4 Cluster state transitions

| Transition | Lease state | Export state | ublk device |
|---|---|---|---|
| Initial | None | None | None |
| Acquire writer lease | Writer | None | None |
| START_DEV | Writer | Active (RW) | `/dev/ublkb<N>` present |
| Lease lost (partition) | None | Fenced → Stopped | Removed |
| Re-acquire lease | Writer | None | None (requires re-export) |
| Graceful shutdown | Writer → None | Stopped → None | Removed |

## 9. Dynamic Block Size Mapping

### 9.1 Problem

tidefs internally uses variable-sized extents (recordsize, typically 128 KiB) while
ublk exposes a fixed logical block size (typically 4 KiB). A write that is not aligned
to the internal extent boundary requires read/modify/write.

### 9.2 Algorithm

```
fn block_write_misaligned(
    engine: &VfsEngine,
    inode: InodeId,
    start_block: u64,
    block_count: u32,
    buf: &[u8],
    block_size: u32,
    extent_boundary: u64,  // next extent boundary after start_block
) -> Result<(), Error> {
    let byte_offset = start_block * block_size;
    let write_len = block_count * block_size;

    if byte_offset + write_len <= extent_boundary {
        // Fully within extent → direct write
        engine.block_write(inode, start_block, block_count, buf)
    } else {
        // Split at extent boundary
        let aligned_blocks = (extent_boundary - byte_offset) / block_size;
        let aligned_bytes = aligned_blocks * block_size;

        // Write aligned prefix
        engine.block_write(inode, start_block, aligned_blocks, &buf[..aligned_bytes])?;

        // Recurse for remainder
        let next_extent = engine.extent_boundary_after(inode, extent_boundary)?;
        block_write_misaligned(
            engine, inode,
            start_block + aligned_blocks,
            block_count - aligned_blocks,
            &buf[aligned_bytes..],
            block_size,
            next_extent,
        )
    }
}
```

The RMW path is triggered only when:

1. The write start is not aligned to `recordsize`
2. The write end is not aligned to `recordsize`
3. The write spans an extent boundary

In the RMW case:
1. Read the partial extent(s) from the engine
2. Modify the affected bytes with the write buffer
3. Write the full extent(s) back to the engine

This is an internal optimization detail, not a protocol concern. The ublk consumer
sees only the fixed logical block size.

## 10. Daemon Topology

### 10.1 Process model

The `tidefs-ublk` daemon is a peer to the FUSE adapter daemon (#1145) in the daemon
topology. Both daemons:

- Connect to the same `tidefs-local-filesystem` engine instance (or cluster engine)
- Implement the `VfsEngine` trait
- Emit traces at the VfsEngine boundary in the format defined by #1235
- Hold appropriate leases (#1209) for their mutation domain

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  FUSE Daemon │  │  ublk Daemon │  │  Admin Proxy │
│  (tidefsfuse)│  │ (tidefs-ublk)│  │  (tidefsadm) │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │ VfsEngine trait
              ┌──────────▼──────────┐
              │  tidefs-local-      │
              │  filesystem engine  │
              └─────────────────────┘
```

### 10.2 Startup sequence

1. Daemon connects to the engine (local or cluster)
3. Daemon reads volume_index to discover exportable volumes
4. For each volume marked for auto-export, acquire lease and start device
5. Enter control loop (accept admin commands, monitor lease health)

### 10.3 Admin commands

The daemon accepts admin commands via a Unix domain socket:

| Command | Description |
|---|---|
| `LIST_VOLUMES` | List all volumes and their export status |
| `EXPORT_VOLUME <uuid> [ro\|rw]` | Export a volume via ublk |
| `UNEXPORT_VOLUME <uuid>` | Stop exporting a volume |
| `RESIZE_VOLUME <uuid> <new_sectors>` | Resize an exported volume |
| `GET_VOLUME_STATUS <uuid>` | Get detailed volume + export status |
| `DAEMON_STATUS` | Get daemon health, queue stats, lease state |

## 11. Error Handling and Edge Cases

### 11.1 Misaligned requests

All block IO requests must be aligned to `logical_block_size`. Misaligned requests
receive `UBLK_IO_RES_ABORT` (−EINVAL). The kernel block layer already enforces
alignment; this is a defense-in-depth check.

### 11.2 Out-of-bounds access

Reads or writes beyond the current volume size receive `UBLK_IO_RES_ABORT` (−EIO).

### 11.3 Discard on read-only volumes

Discard on a volume with `READ_ONLY` flag or exported read-only returns
`UBLK_IO_RES_ABORT` (−EPERM).

### 11.4 Concurrent export attempt

If two ublk daemon instances attempt to export the same volume RW, the volume_index
CAS operation fails for the second instance. The second instance receives an error
and does not start the device.

### 11.5 Crash during export

If the ublk daemon crashes while a device is active:

1. Kernel detects the ublk daemon fd closure (via `UBLK_CMD_START_USER_RECOVERY`
   if enabled, or direct device removal)
2. Kernel removes `/dev/ublkb<N>` from the namespace
3. On daemon restart, the volume_index may still show `export_state = Some(...)`
   for the stale export
4. The stale export entry is detected by comparing `exporter_node` against the
   current node UUID; if it matches, the stale entry is cleared
5. The volume can be re-exported normally


### 12.1 Existing test infrastructure

The `tidefs-block-volume-adapter-core` crate already contains deterministic model
tests covering:

- **OW-301A**: read/write/flush/discard geometry bounds, exact data, discard/zero visibility
- **OW-301B**: queue admission, shard, backpressure, fence gates
- **OW-301C**: dispatch execution for admitted requests
- **OW-301D**: export lifecycle (quiesce, fence, resume)
- **OW-301E**: cache coherency (cache, barrier, guard)
- **OW-301F**: resize/fence transition (capacity target, drain, geometry publication)
- **OW-301N**: file-backed image surface binding (without live ublk)

The `tidefs-block-volume-adapter-ublk-control-runtime` crate contains tests covering:

- Device lifecycle (add, set_params, start, stop, del)
- fetch_req loop (io_uring submission, cqe handling)
- Error injection (io_uring failures, queue full, errno return paths)
- Resize control path

### 12.2 Additional gates

| Gate | Description | Implementation |
|---|---|---|
| OW-301H | Volume index CRUD (insert, lookup, delete, scan) | Same |
| OW-301J | Export lock acquire/release/fence under lease transitions | Same |
| OW-301K | Dynamic block size mapping (RMW correctness) | Same |
| OW-301L | VfsEngine block contract (all 6 ops through trait boundary) | Integration test with `tidefs-local-filesystem` |
| OW-301M | Cluster fencing (lease loss → export stop → device removal) | Requires cluster simnet #1175 |

## 13. Implementation Plan

### Phase 1: Volume model and index (this issue)

- Define `TLV_VOLUME` on-media format in the on-media format strategy (#1218)
- Implement `volume_index` B+tree in `tidefs-block-volume-adapter-core`
- Add `org.tidefs:volumes` and `org.tidefs:volumes-strict` feature flags
- Implement volume create/destroy through admin API
- Tests: OW-301G, OW-301H

### Phase 2: VfsEngine block contract

- Add `VfsEngineBlock` trait to `tidefs-types-vfs-core`
- Implement block ops in `tidefs-local-filesystem` (extent map mapping)
- Wire ublk IO loop to VfsEngine block ops
- Tests: OW-301L

### Phase 3: Export locks and cluster safety

- Integrate lease subsystem (#1209) with export lock manager
- Implement fencing on lease loss
- Tests: OW-301J, OW-301M

### Phase 4: Dynamic block size mapping

- Implement RMW for misaligned writes
- Tests: OW-301K

## 14. References

| Reference | Description |
|---|---|
| Linux ublk documentation | `Documentation/block/ublk.rst` in kernel tree |
| `tidefs-ublk-abi` crate | Linux ublk UAPI mirror (`UBLK_CMD_*`, `UBLK_IO_OP_*`, param structs) |
| `tidefs-block-volume-adapter-core` crate | Deterministic block volume model (gates OW-301A–OW-301N) |
| `tidefs-block-volume-adapter-ublk-control-runtime` crate | io_uring control plane (add/set/start/stop/del dev) |
| `tidefs-block-volume-adapter-daemon` app | Daemon binary tying model + control runtime |
| Issue #1213 | VFS Engine API contract (29-operation trait boundary) |
| Issue #1209 | MEMBERSHIP/lease system (term, epoch) fencing |
| Issue #1145 | Daemon topology (peer daemon model) |
| Issue #1235 | Trace emission contract (JSONL format at VfsEngine boundary) |
| Issue #1218 | On-media format strategy (TLV encodings) |
