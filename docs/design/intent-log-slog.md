# Intent Log and Separate Log Device (LOG_DEVICE) — Design Specification

**Issue**: [#1252](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1252)
**Status**: design-spec
**Priority**: P1
**Lane**: storage-core
**Depends on**: #1220 (on-media format), #1267 (commit_group state machine), PC-008 (sync write latency model)

## Abstract

The intent log is the durability fast-path for synchronous writes. It decouples
fsync/O_DSYNC latency from the main transaction group (commit_group) commit cycle, which
may batch seconds of accumulated writes. ZFS achieves sub-100us fsync latency
via its ZIL (ZFS Intent Log) on a dedicated log device; tidefs must match or
beat this. CephFS has no equivalent — all sync writes traverse the full
replication path. This design specifies the intent log architecture, log device
model, record format, crash recovery contract, cluster-aware semantics, and
integration with the commit_group state machine.

---

## 1. Architecture

### 1.1 Two-path durability model

tidefs provides two durability paths, both correct but with different latency
profiles:

```
                    ┌──────────────────┐
  fsync / O_DSYNC ──┤  INTENT LOG      │──→ <100us on LOG_DEVICE NVMe
  O_SYNC            │  (fast path)     │
                    │  small records   │
                    │  batched commits │
                    └──────┬───────────┘
                           │ background fold
                           ▼
                    ┌──────────────────┐
  commit_group commit        │  COMMIT_GROUP COMMIT      │──→ batched, large,
  (periodic) ───────┤  (batched path)  │    throughput-optimized
                    │  full journal    │
                    │  checkpoint      │
                    └──────────────────┘
```

- **Intent log**: receives synchronous writes, persists them to fast media,
  acks the caller, then folds into the next commit_group commit.
- **CommitGroup commit**: the main batched commit pipeline defined in #1267. Receives
  all writes (sync and async) and produces full journal segments with
  checkpoint pointers.

The key insight: fsync latency is decoupled from commit_group commit latency. The intent
log absorbs small sync writes at low latency; the commit_group commit handles batching
and throughput.

### 1.2 What goes to the intent log

Only **synchronous durability requests** go to the intent log:

| Operation | Intent log? | Notes |
|---|---|---|
| `fsync(fd)` | Yes | Drains all dirty ranges for fd |
| `fdatasync(fd)` | Yes | File data only; may omit metadata |
| `O_DSYNC` write | Yes | Per-write data integrity |
| `O_SYNC` write | Yes | Per-write data + metadata integrity |
| `MS_SYNC` msync | Yes | Shared mmap dirty ranges |
| `sync()` / `syncfs()` | Yes | All dirty inodes |
| rename, unlink, etc. | Yes | Namespace operations need durability |
| Async write (no flag) | No | Goes straight to commit_group batch |
| mmap write (no msync) | No | Dirty page; no durability request |

### 1.3 Intent log record lifecycle

```
   APPEND ──→ FLUSH ──→ ACK ──→ [commit_group sync picks up] ──→ TRIM
     │          │        │
     │    fsync/fdatasync │
     │    on zil segment  │
     │                    │
     └── record written   └── caller sees "durable"
         to in-memory
         zil buffer
```

1. **APPEND**: record is appended to the in-memory zil buffer for the dataset
2. **FLUSH**: on fsync/fdatasync boundary, the buffer is written to the zil
   segment and flushed (fsync/fdatasync on the segment file)
3. **ACK**: caller receives the durable completion acknowledgment
4. **FOLD**: at the next commit_group commit boundary (SYNC phase, step 3 of the commit_group
   state machine), intent log records are folded into the main metadata journal
5. **TRIM**: after the commit_group commit checkpoint is durable, intent log records
   from that commit_group and earlier are trimmed (space reclaimed)

---

## 2. LOG_DEVICE Device Model

### 2.1 Device class

A log device (Separate LOG) device is a dedicated storage device for the intent log.
It must provide low-latency synchronous writes:

| Property | Requirement |
|---|---|
| Media class | `LOG` (separate from `DATA` and `METADATA`) |
| Latency | < 50us fsync (NVMe Optane, NVDIMM, or battery-backed DRAM) |
| Endurance | High write endurance (intent log is write-intensive) |
| Minimum devices | 1 (mirrored: 2) |
| Redundancy | Mirror only (no parity — latency-critical) |

### 2.2 Pool configuration

```toml
[pool.log_devices]
devices = ["/dev/nvme1n1", "/dev/nvme2n1"]
mode = "mirror"       # only mirror supported
fallback = "mainpool" # use main pool devices if LOG_DEVICE missing
```

### 2.3 LOG_DEVICE failure semantics

- **Missing LOG_DEVICE on import**: the intent log falls back to the main pool
  devices. Performance degrades (intent log writes land on slower media) but
  correctness is preserved.
- **log device failure during operation**: the intent log transparently
  fails over to the mirror (if mirrored) or falls back to main pool devices.
  In-flight intent log records are not lost because they haven't been acked
  yet — the caller retries.
- **Partial LOG_DEVICE loss on crash**: intent log records on the surviving LOG_DEVICE
  device (or main pool) are replayed. Records only on the lost device were
  never acknowledged as durable.

### 2.4 LOG_DEVICE write batching

Multiple fsync calls that arrive while a log device write is in flight are batched
into a single LOG_DEVICE segment flush. This is the key to sub-100us amortized
latency:

```
Time ──────────────────────────────────────────→
fsync(fd1) ─┐
fsync(fd2) ─┤── batched into one LOG_DEVICE write
fsync(fd3) ─┘     │
                  ├── LOG_DEVICE write (50us)
                  ├── LOG_DEVICE flush (20us)
                  │
                  ├── ack fd1 (70us)
                  ├── ack fd2 (70us)
                  └── ack fd3 (70us)
```

The batching window is adaptive: 50us minimum, up to 500us under load, with a
maximum of 64 records per batch.

---

## 3. Intent Log Record Format

### 3.1 ZilRecord V1

The intent log record uses the V1 format framework defined in #1220. It is
record family `1`, type `7`.

| Field | Offset | Size | Description |
|---|---:|---:|---|
| `family_id` | 0 | 2 | `1` |
| `type_id` | 2 | 2 | `7` (ZilRecord) |
| `record_len` | 4 | 4 | Total record length including payload |
| `commit_group` | 8 | 8 | Transaction group this record belongs to |
| `dataset_id` | 16 | 16 | Dataset UUID |
| `object_id` | 32 | 8 | Inode number |
| `logical_offset` | 40 | 8 | Byte offset within the file |
| `payload_len` | 48 | 4 | Length of payload data |
| `flags` | 52 | 2 | ZIL flags (see §3.2) |
| `checksum` | 54 | 4 | CRC32C of fixed prefix (bytes 0..54) |
| `payload` | 58 | — | Variable: new content [payload_len]u8 |
| `tlv_area` | varies | — | TLV extension area |

Fixed prefix: 58 bytes. Minimum alignment: 8 bytes.

### 3.2 ZIL flags

| Bit | Name | Description |
|---|---:|---|
| 0 | `ZIL_FLAG_DATA` | Record contains data payload |
| 1 | `ZIL_FLAG_METADATA` | Record contains metadata delta (inode, extent map) |
| 2 | `ZIL_FLAG_NAMESPACE` | Namespace operation (rename, link, unlink) |
| 3 | `ZIL_FLAG_TRUNCATE` | Truncate operation |
| 4 | `ZIL_FLAG_SETATTR` | Attribute change (mode, owner, timestamps) |
| 5-15 | reserved | Zero |

### 3.3 Namespace record extension

When `ZIL_FLAG_NAMESPACE` is set, the TLV area carries:

```
TLV_TYPE_NAMESPACE (100):
  op: u8           # 0=rename, 1=link, 2=unlink, 3=symlink, 4=mkdir, 5=rmdir
  parent_ino: u64  # source parent inode
  target_ino: u64  # target inode (may differ from object_id for rename target)
  name_len: u16    # name length
  name: [u8; name_len]
```

### 3.4 Idempotency

Intent log replay is idempotent by construction:

- Each record carries `(dataset_id, object_id, logical_offset)` — replaying
  the same write to the same offset produces the same result.
- Namespace records carry the full operation — replaying a rename that already
  happened is a no-op (target already exists, source already gone).
- The commit_group number ensures records from an already-folded commit_group are skipped during
  replay.

---

## 4. Crash Recovery Integration

### 4.1 Recovery order

On crash, recovery proceeds in this order:

1. **Intent log replay**: all records in the zil segment(s) with commit_group > last
   checkpoint commit_group are replayed into the live filesystem state. This restores
   any sync writes that were acked but not yet folded into a commit_group commit.
   checkpoint pointer. Any commit records with commit_group > last checkpoint are
3. **Orphan cleanup**: inodes with `orphan_commit_group > 0` that have no directory
   entries are purged.
4. **Online**: the filesystem is mounted and accepts new writes.

### 4.2 Intent log replay algorithm

```
function replay_intent_log(dataset):
    zil_segments = discover_zil_segments(dataset)
    last_checkpoint_commit_group = dataset.checkpoint_commit_group

    for segment in zil_segments:
        for record in segment:
            if record.commit_group <= last_checkpoint_commit_group:
                continue  # already folded into a committed commit_group

            if record.flags & ZIL_FLAG_DATA:
                apply_data_write(record)

            if record.flags & ZIL_FLAG_METADATA:
                apply_metadata_delta(record)

            if record.flags & ZIL_FLAG_NAMESPACE:
                apply_namespace_op(record)

            if record.flags & ZIL_FLAG_TRUNCATE:
                apply_truncate(record)

            if record.flags & ZIL_FLAG_SETATTR:
                apply_setattr(record)

    # After replay, schedule immediate commit_group commit to fold replayed
    # records into the main journal and trim the zil
    schedule_commit_group_commit(dataset)
```

### 4.3 Trim after commit

After the commit_group commit that folds intent log records completes:

1. The main journal now contains all data from the intent log records.
2. The intent log records become redundant.
3. The zil segment is trimmed: the segment file is either truncated (if it's
   the active segment) or unlinked (if it's a previous segment).
4. Trim happens atomically with the checkpoint pointer update — if a crash
   occurs before trim, the replay simply re-processes already-folded records
   (idempotent, harmless).

---

## 5. Cluster-Aware Intent Log

### 5.1 Writer-node ownership

In a distributed deployment, the writer node that holds the dataset lease owns
the intent log for that dataset. Intent log records are NOT broadcast through
the full consensus path — that would defeat the latency purpose.

### 5.2 Fast-path replication

For cross-node durability without the latency penalty of full consensus,
the intent log supports optional synchronous mirroring to one follower:

```
 Writer Node                  Follower Node
 ────────────                 ──────────────
 zil_append(record)
     │
     ├──→ zil_mirror(record) ──→ append to follower zil
     │         │                      │
     │         │                      ├── flush
     │         │                      └── ack
     │         │
     │    [both flushed]
     │         │
     └── ack to caller
```

- Mirror count: 1 follower (not a quorum — latency-critical)
- If follower is unreachable: fall back to local-only durability (degraded
  but not blocked)
- `ack_level = 1`: local flush only (default)
- `ack_level = 2`: local + follower flush (higher durability, ~2x latency)

### 5.3 Leader failover

When the writer node fails and a new leader is elected:

1. New leader replays the old writer's intent log from the last known zil
   segment
2. If the old writer used `ack_level = 2`, the follower already has the records
3. If `ack_level = 1`, records only on the dead writer are lost — this is
   acceptable because those records were acked at durability level 1 (local
   device only, not cross-node)
4. After replay, the new leader takes ownership and begins accepting writes

---

## 6. Performance Targets

### 6.1 Latency

| Metric | Target | Condition |
|---|---|---|
| fsync latency | < 100us | NVMe LOG_DEVICE, 4KB write |
| fsync latency | < 500us | Main pool device (no LOG_DEVICE) |
| O_DSYNC write | < 100us | NVMe LOG_DEVICE |
| Batching overhead | < 10us | Per-additional fsync in batch |
| Trim overhead | 0us | Async, post-commit |

### 6.2 Throughput

| Metric | Target |
|---|---|
| Intent log write throughput | 1M IOPS (NVMe LOG_DEVICE) |
| Batched fsync throughput | 500K fsync/sec (64-record batching) |
| CommitGroup fold throughput | Limited by main journal, not intent log |

### 6.3 Space

| Metric | Bound |
|---|---|
| Intent log size | Min: 64MB, Max: 1% of pool size or 4GB (whichever is smaller) |
| Record overhead | 58 bytes fixed prefix per record |
| Segment size | 16MB per zil segment |

---

## 7. Integration with CommitGroup State Machine

The intent log integrates with the commit_group state machine (#1267) at specific
points:

### 7.1 During OPEN phase

- Sync writes append to the intent log buffer
- The intent log buffer is NOT part of the commit_group's dirty set — it's a separate
  fast-path structure
- fsync/fdatasync trigger zil segment flush independently of commit_group state

### 7.2 During QUIESCE phase

- New sync writes are still accepted (they go to the next commit_group's intent log)
- The current commit_group's intent log buffer is sealed — no more records can be added
  to it

### 7.3 During SYNC phase

- **Step 3 variant**: when folding intent log records, metadata updates from
  the intent log are merged into the main metadata journal before the commit
  record is written
- The intent log records supply the "before" state for crash recovery: if
  the commit_group commit fails partway through, the intent log records are still
  available for replay

### 7.4 After checkpoint

- Intent log records from the committed commit_group (and earlier) are trimmed
- The zil segment space is reclaimed

---

## 8. Integration with V1 Format Strategy

The ZilRecord is record family `1`, type `7` in the V1 format framework
(#1220). It follows all V1 format rules:

- 8-byte dispatch prefix (family_id + type_id + record_len)
- Fixed-width little-endian scalar fields
- Per-record CRC32C covering the fixed prefix
- TLV extension area for namespace operations and future extensions
- Dataset-level feature flags: `INTENT_LOG_LOG_DEVICE` (ro_compat — pools without
  LOG_DEVICE support can mount read-only)

### 8.1 Feature flag

```
INTENT_LOG_LOG_DEVICE  (ro_compat bit 3)
```

Pools created with log devices set this flag. Pools without log devices do
not set it. A reader that doesn't understand log device can mount read-only; writing
requires LOG_DEVICE support.

---

## 9. Relationship to PC-008

PC-008 defines the **sync write latency law** — the rules that bound how sync
writes interact with durability. This design is the **implementation** of that
law:

| PC-008 rule | This design |
|---|---|
| sync-write-range | ZilRecord with DATA flag at (object_id, logical_offset) |
| odsync-data-range | Same as sync-write-range; metadata omitted from this record |
| fsync-dirty-drain | All dirty ranges for fd flushed to zil segment before ack |
| shared-mmap-msync-sync | MS_SYNC issues ZilRecord for each dirty page range |
| namespace-sync-intent | ZilRecord with NAMESPACE flag; TLV carries full operation |
| pressure-fallback | If zil buffer full, fall back to full commit_group commit |
| crash-replay-reconcile | §4.2 idempotent replay algorithm |

---

## 10. Non-Claims

This design does not cover:

- **Kernel-space intent log**: the current design is userspace-only. A kernel
  intent log (e.g., for ublk or future kernel module) would follow the same
  record format but with different flush mechanics.
- **RDMA-accelerated LOG_DEVICE mirroring**: the mirror path is TCP-based. RDMA
  would further reduce cross-node latency.
- **Encrypted intent log**: encryption is deferred to #1246 (encryption-at-rest).
  When implemented, ZilRecord payloads will be encrypted with the dataset key.
- **Compressed intent log payloads**: compression is deferred to #1245.

---

## 11. References

- `docs/design/on-media-format-strategy.md` — V1 format framework (#1220)
- `docs/design/canonical-commit-ordering-commit_group-state-machine.md` — CommitGroup state machine (#1267)
- `docs/INTENT_LOG_SYNC_WRITE_LATENCY_PC008.md` — Sync write latency law (PC-008)
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md` — Checkpoint persistence
- Issue #1246 — Encryption-at-rest design
- Issue #1245 — Compression design strategy
- Issue #1224 — Torn-commit recovery
