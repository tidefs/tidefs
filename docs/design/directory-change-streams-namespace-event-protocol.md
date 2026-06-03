# Directory Change Streams Namespace Event Protocol

**Maturity: design-spec**. Rust implementation deferred to successor issues.

**Issue:** #3395
**Lineage:** closes the standalone design gap previously referenced as #1173
**Lane:** storage-core
**Kind:** design

## Motivation

TideFS has multiple consumers that need the same fact: a namespace or file
metadata mutation happened, in a precise order, against a precise dataset and
directory. Without a first-class change stream, each consumer is forced to
infer changes from a different surface:

| Consumer | Without change streams | Failure mode |
| --- | --- | --- |
| FUSE notify | Watches individual adapter operations | Cannot replay after reconnect or crash |
| Replication/send | Scans namespace state after the fact | Expensive full-tree deltas |
| Audit/compliance | Hooks ad hoc call sites | Gaps when new mutation paths are added |
| Derived views | Rebuilds whole views on version mismatch | Hot-directory performance cliff |

Directory change streams solve this by making every committed namespace,
attribute, xattr, and file-range mutation produce one ordered, durable event.
The stream is not a separate authority for filesystem state. Authoritative
state remains in inode records, directory indexes, extent maps, xattr storage,
and committed-root/intent-log machinery. The stream is a replayable delta feed

## Architecture

### 1. Authority Boundary

The mutation path owns event publication. A mutating operation writes its normal
authoritative state and appends one or more `DirChangeEventV1` records inside
caches, but it must not treat a change-stream event as proof that the
authoritative state update exists until the transaction group is committed.

The required commit ordering is:

2. Build the corresponding `DirChangeEventV1` records.
3. Append records to the per-directory stream and dataset sequence index in
   the same transaction group.
4. Publish the transaction group committed root.
5. Notify live consumers that new events are available.

If step 4 does not complete, neither authoritative state nor the matching
change-stream events are visible after recovery.

### 2. Event Classes

The canonical event type set is:

| Event type | Required payload | Primary consumers |
| --- | --- | --- |
| `CreateFile` | parent directory, name, created inode, mode | FUSE entry notify, derived views, audit |
| `UnlinkFile` | parent directory, name, unlinked inode, prior nlink | FUSE delete/entry notify, reclaim, audit |
| `CreateDir` | parent directory, name, created inode, mode | FUSE entry notify, derived views |
| `RemoveDir` | parent directory, name, removed inode | FUSE entry notify, audit |
| `CreateSymlink` | parent directory, name, inode, target hash/length | replication, audit |
| `HardLink` | parent directory, name, target inode, new nlink | FUSE entry notify, audit |
| `SetAttr` | inode, attribute mask, old/new selected values | FUSE inode notify, audit |
| `XattrSet` | inode, namespace/name hash, value length | FUSE inode notify, audit |
| `XattrRemove` | inode, namespace/name hash | FUSE inode notify, audit |

`RenameFile` is a single event even when it affects two directories. It is
indexed under both the old and new parent directories, but its event id is
singular so consumers cannot observe a half-rename.

### 3. Ordering Model

Each dataset has a monotonic `stream_seq` assigned at event append time. Each
directory has a monotonic `dir_stream_seq` assigned for events indexed under
that directory. Consumers choose the ordering domain they need:

| Ordering domain | Use |
| --- | --- |

The dataset stream is total per dataset and ordered by `(txg_id, stream_seq)`.
Per-directory streams preserve the projection of dataset order for that
directory. Per-inode range streams preserve write/truncate order for a file.

### 4. Storage Layout

The design uses two durable indexes:

1. `DatasetChangeLog`: append-only event records ordered by dataset stream id.
2. `DirectoryChangeRing`: bounded per-directory ring of event ids plus compact
   per-event projection data for fast view refresh.

The dataset log is the replay authority for consumers that need every event.
The directory ring is a bounded acceleration structure. When a directory ring
overflows, old entries are evicted oldest-first, and consumers that lag behind

Default ring capacity is 64K events per directory. Implementations may lower
the capacity for tiny datasets or raise it for explicitly provisioned hot
directories, but the configured maximum is part of dataset policy and charged
to the metadata budget.

### 5. Live Publication

After commit, the stream publisher wakes registered consumers whose filter
matches the appended event classes. Waking a consumer is best-effort; durable
cursor state is the source of truth. A consumer that misses a wakeup polls by

Live publication is in-process for local consumers and feeds the cluster
not open network sessions and does not duplicate transport authentication.

### 6. Consumer Cursors

Every consumer has a named cursor:

```
ChangeStreamCursor:
  consumer_id: ConsumerId
  dataset_id: DatasetId
  filter_mask: ChangeStreamFilter
  last_dataset_seq: u64
  per_directory_low_water: optional map<InodeId, u64>
  lease_epoch: u64
  flags: durable | ephemeral
```

Durable consumers such as audit and replication persist cursor advancement.
Ephemeral consumers such as a FUSE notify session may keep cursors in memory
and resubscribe after mount/session restart.

### 7. Overflow and Resync

Overflow is explicit, not silent. If a consumer polls from a cursor older than
The consumer must rebuild from authoritative state:

| Consumer | Resync behavior |
| --- | --- |
| Derived directory view | Drop view and rebuild from directory index |
| Replication | Fall back to snapshot/send delta for the affected range |
| Audit | Report audit gap and require durable audit-log configuration fix |

## Data Structures

### Stable identifiers

```rust
#[repr(transparent)]
pub struct DatasetId([u8; 16]);

#[repr(transparent)]
pub struct InodeId(u64);

#[repr(transparent)]
pub struct TxgId(u64);

#[repr(transparent)]
pub struct ChangeStreamSeq(u64);

#[repr(transparent)]
pub struct ConsumerId([u8; 16]);
```

### Event record format

```rust
#[repr(C)]
pub struct DirChangeEventV1 {
    pub magic: [u8; 4],              // "VDCS"
    pub version: u8,                 // 1
    pub event_type: ChangeEventType,
    pub flags: u16,
    pub record_len: u32,

    pub txg_id: TxgId,
    pub stream_seq: ChangeStreamSeq,
    pub timestamp_ns: u64,
    pub dataset_id: DatasetId,

    pub dir_ino: InodeId,
    pub entry_name_hash: [u8; 32],
    pub target_ino: InodeId,

    pub payload_len: u32,
    pub event_payload: [u8],
    pub blake3_checksum: [u8; 32],
}
```

`blake3_checksum` covers the serialized record header and payload except the
checksum field itself. It is a durable integrity checksum only. It is not an

`entry_name_hash` uses the canonical namespace-name hashing policy for lookup
acceleration and privacy-preserving filters. Full names remain in payloads

### Event payloads

Payloads are versioned by `(event_type, version)`. Multi-name payloads store
length-prefixed UTF-8/byte names exactly as accepted by the namespace layer.
All integer fields are little-endian.

```rust
CreatePayload:
  name_len: u16
  name: [u8; name_len]
  mode: u32
  uid: u32
  gid: u32

UnlinkPayload:
  name_len: u16
  name: [u8; name_len]
  prior_nlink: u32

CreateDirPayload:
  name_len: u16
  name: [u8; name_len]
  mode: u32
  uid: u32
  gid: u32

RemoveDirPayload:
  name_len: u16
  name: [u8; name_len]

CreateSymlinkPayload:
  name_len: u16
  name: [u8; name_len]
  target_len: u16
  target_hash: [u8; 32]

HardLinkPayload:
  name_len: u16
  name: [u8; name_len]
  new_nlink: u32

RenamePayload:
  old_dir_ino: u64
  old_name_len: u16
  old_name: [u8; old_name_len]
  new_dir_ino: u64
  new_name_len: u16
  new_name: [u8; new_name_len]
  rename_flags: u32

SetAttrPayload:
  attr_mask: u64
  old_size: optional u64
  new_size: optional u64
  old_mode: optional u32
  new_mode: optional u32
  old_uid: optional u32
  new_uid: optional u32
  old_gid: optional u32
  new_gid: optional u32
  old_atime_ns: optional u64
  new_atime_ns: optional u64
  old_mtime_ns: optional u64
  new_mtime_ns: optional u64

WritePayload:
  offset: u64
  length: u64
  data_generation: u64

TruncatePayload:
  old_size: u64
  new_size: u64
  data_generation: u64

XattrPayload:
  namespace: u8
  name_hash: [u8; 32]
  name_len: u16
  name: [u8; name_len]
  value_len: optional u32
```

### Per-directory event ring

```rust
pub struct DirectoryChangeRing {
    pub dataset_id: DatasetId,
    pub dir_ino: InodeId,
    pub capacity_events: u32,       // default 65536
    pub low_water_dir_seq: u64,
    pub next_dir_seq: u64,
    pub entries: Ring<DirectoryEventRef>,
}

pub struct DirectoryEventRef {
    pub dir_seq: u64,
    pub stream_seq: ChangeStreamSeq,
    pub txg_id: TxgId,
    pub event_type: ChangeEventType,
    pub target_ino: InodeId,
    pub entry_name_hash: [u8; 32],
}
```

## Algorithms

### Recording an event

```
record_change(mutation, txg):
  event = build_event(mutation, txg.id, now_ns())
  event.stream_seq = dataset_log.reserve_next_seq()
  event.blake3_checksum = checksum(event_without_checksum)

  txg.append(dataset_log, event)
  for dir in projection_dirs(event):
    dir_seq = directory_ring[dir].reserve_next_seq()
    txg.append(directory_ring[dir], DirectoryEventRef(event, dir_seq))

  txg.on_commit:
    wake_consumers(event.filter_bits)
```

The mutation commit is invalid if the event append fails. This makes change
streams part of the filesystem mutation contract rather than an optional side
effect.

### Consumer API

```
register_consumer(consumer_id, filter_mask) -> cursor
poll(cursor, max_events, max_bytes) -> events[] | Lagged
advance(cursor, last_event_id) -> cursor
unregister_consumer(cursor)
```

`poll` is non-mutating. `advance` is the only operation that persists cursor
progress. This lets a consumer read a batch, process it, and only then advance.
If a consumer crashes after `poll` and before `advance`, it may receive the
same events again; consumers must be idempotent by `(dataset_id, stream_seq)`.

### Filtering

`filter_mask` contains event-class bits:

| Bit | Class |
| --- | --- |
| 0 | Namespace entry mutations |
| 1 | Attribute mutations |
| 2 | Data range mutations |
| 3 | Xattr mutations |
| 4 | Directory topology mutations |
| 5 | Audit-only detail payloads |

The publisher uses the mask only to avoid waking consumers unnecessarily. A
consumer cursor may still poll and discard unneeded events if it shares a
durable stream with other consumers.

### Crash recovery

On mount/replay:

1. Replay committed transaction groups normally.
2. Rebuild in-memory publisher state from consumer cursor records.
4. Rebuild directory ring heads and low-water marks from durable ring metadata.
5. For any incomplete ring tail, truncate to the last checksum-valid record and
   force `Lagged` for cursors whose range intersects the truncation.

No consumer wakeups are replayed. Consumers discover new work by polling their
cursor after mount/session restoration.

## Tradeoffs

### Per-directory rings plus dataset log

Maintaining both structures costs extra metadata writes, but it avoids forcing
hot directory views to scan the full dataset stream. The dataset log remains
the complete order for audit/replication, while directory rings provide bounded
low-latency refresh.

### Oldest-first eviction

Oldest-first eviction is simple and predictable. It can force slow consumers to
resync, but it prevents unbounded metadata growth. The alternative, pinning
events for every consumer, would let a dead audit cursor exhaust metadata
memory and block normal namespace mutations.

### Checksummed records

Each record carries a BLAKE3 checksum to detect torn or corrupt stream records
during replay. This duplicates some lower-layer integrity coverage, but it
lets the stream fail closed at record granularity and report the exact corrupt
event. The checksum is not an authenticity mechanism.

### Audit gaps

Bounded rings conflict with audit completeness. The resolution is that audit
consumers use the dataset log with durable cursor retention and separate
capacity policy; per-directory ring overflow does not justify dropping audit
events silently.

## Dependencies

| Dependency | Contract |
| --- | --- |
| Transaction group / committed root | Events become visible only with the mutation txg |
| Directory index | Rebuild source for lagged directory views |
| Inode attributes and extent map | Rebuild source for attr and range lag |
| Derived views (#1240) | Uses per-directory streams for incremental refresh |
| FUSE notify runtime | Converts local event classes to `FUSE_NOTIFY_INVAL_*` calls |
| Replication/send | Uses dataset stream as the ordered mutation delta source |
| Audit logging | Uses durable dataset stream cursor and reports gaps explicitly |
| Resource governor | Charges ring memory and consumer lag to metadata budgets |

## Integration Contracts


fallback cursor per writer term. It maps:

| --- | --- |
| Create/unlink/link/symlink in a directory | `entry_inval(parent, name)` |
| Rename across one or two directories | `entry_inval(old_parent, old_name)` and `entry_inval(new_parent, new_name)` |
| Directory topology change | `dir_rev(parent)` |
| SetAttr/truncate/xattr | `inode_inval(inode, attr_mask)` |
| Write | `range_inval(inode, offset, length)` if supported, otherwise `inode_inval` |

complete.

### FUSE notify

The FUSE adapter subscribes for mounted datasets. It may use ephemeral cursors
FUSE notify must preserve event order within a directory so lookup/readdir

### Replication and send

Replication consumes the dataset stream by `(txg_id, stream_seq)` and treats
events as delta hints. Before sending a delta, it reads authoritative inode,
directory, xattr, or extent state at the referenced committed root. If its
comparison rather than using incomplete deltas.

### Audit

Audit registers a durable cursor and an explicit retention policy. If audit
surfaces an operator-visible health error. Per-directory ring overflow must not
be reported as audit loss unless the dataset log retention is also exceeded.

### Derived views

Derived directory views store the last applied `dir_stream_seq`. On access,
if the directory's current sequence is newer, the view builder polls the
directory ring from the stored sequence. Small deltas are applied
incrementally; large deltas or `Lagged` force a full rebuild from the directory
index.


The implementation successor must include:

1. Unit tests for every event payload encoder/decoder and checksum failure.
2. Transaction tests proving mutation and event append commit or roll back
   together.
3. Per-directory ring tests for default capacity, oldest-first eviction, and
   `Lagged` reporting.
4. Consumer cursor tests for idempotent poll/advance and durable cursor replay.
5. Rename tests proving one event projects into both parent directories without
   half-rename visibility.
6. FUSE notify mapping tests for entry, inode, directory, and range events.
8. Derived-view refresh tests proving small deltas apply incrementally and
   overflow forces full rebuild.
9. Replication/send tests proving events are hints and authoritative state is
   re-read before sending.
10. Audit retention tests proving lag is visible and never silently dropped.

workspace `cargo check --workspace --locked` to confirm no code path changed.
