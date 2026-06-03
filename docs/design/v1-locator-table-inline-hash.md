# V1 Locator Table (Inline-Hash): Architecture and Implementation Design

Maturity: **design-spec** — specifies the V1 inline-hash locator table engine
implemented in `crates/tidefs-locator-table/`, covering the `V1LocatorTable`
data structure, the `LocatorTableOps` trait contract, monotonic `LocatorId`
integration with extent maps, and the design tradeoffs versus the deferred
V2 B-tree page representation.

This document closes Forgejo issue #1687.

## 1. Problem Statement

Every DATA extent in a TideFS file references a `LocatorId` — a 64-bit opaque
handle stored in `ExtentMapEntryV2.locator_id`. The role of the locator table
is to translate that handle into one or more physical replicas:

```
extent map entry ──► LocatorId ──► locator table ──► [ReplicaPlacement, ...]
                                                         │
                                                         ├─ (node_id, device_id, grain_offset, grain_count)
                                                         ├─ (node_id, device_id, grain_offset, grain_count)
                                                         └─ ...
```

The locator table is **pool-global**: a single table serves all datasets in the
pool. This decoupling is the key architectural advantage over ZFS, where
block pointers embed physical DVAs directly in the extent tree. When TideFS
relocates data (segment retirement, tier migration, rebalance), only the
locator table entry changes — no extent map rewrite is needed.

### 1.1 Two Representation Levels

| Representation | Lifetime | Description |
|---|---|---|
| V1 (inline-hash) | Current | In-memory `BTreeMap<LocatorId, ExtentLocatorValueV1>` with monotonic ID counter. Simple, auditable, single-node. |
| V2 (B-tree page) | Deferred | Persistent on-media B-tree keyed by `LocatorId`, supporting page-level CoW, snapshot isolation, and multi-million-locator scale. |

The V1 representation is the **baseline engine**, suitable for single-node and
development deployments. It implements the full `LocatorTableOps` contract and
to a successor issue and will provide the same trait interface with on-media
persistence.

### 1.2 Dependency Map

| Issue | Name | Relationship |
|-------|------|-------------|
| #1285 | Extent maps and locator tables | Canonical `ExtentLocatorValueV1`, `LocatorTableOps` trait, page layout |
| #1225 / #1566 | V1 extent map tristate model | `ExtentMapEntryV2.locator_id` references locator table |
| #1555 | Polymorphic extent maps | Extent map V2/V3 engines call `LocatorTableOps.resolve()` |
| #1180 | Refcount delta cleanup queues | Locator retirement -> deadlist -> reclaim queue |
| #1286 | Shard groups and rebake | Sharded `ReplicaPlacement` via `ShardPlacement` |
| #1223 | Dataset feature flags | `org.tidefs:locator_table` feature gate |
| #1127 | Spacemap allocator | Locator allocation consumes spacemap grains |

## 2. Core Data Structures

### 2.1 `LocatorId` — Opaque 64-bit Handle

Defined in `tidefs-types-extent-map-core` as a newtype:

```rust
pub struct LocatorId(pub u64);

impl LocatorId {
    pub const NONE: LocatorId = LocatorId(0);
    pub const fn is_none(self) -> bool  { self.0 == 0 }
    pub const fn is_some(self) -> bool  { self.0 != 0 }
}
```

`LocatorId(0)` is the sentinel NONE value, used in `ExtentMapEntryV2` to
indicate entries that have no physical data (UNWRITTEN extents, or entries
whose data has been freed). All allocated locators have `id > 0`.

The 64-bit width supports up to ~1.8×10¹⁹ locators per pool — sufficient for
exabyte-scale storage even with 4 KiB extents.

### 2.2 `ExtentLocatorValueV1` — The Locator Table Record (122 bytes)

The on-media and in-memory locator value is `ExtentLocatorValueV1` (122 bytes,
defined at compile time by `LOCATOR_VALUE_V1_FIXED_SIZE`):

```
Offset  Size  Field
------  ----  -----
 0      8     locator_id: LocatorId       Self-referencing key (for integrity)
 8      8     locator_rev: u64            Monotonic revision counter
16      8     flags: u64                  Bitmask (SHARDED, ERASURE_CODED, COMPRESSED, etc.)
24      2     shard_count: u16            Number of logical shards
26      1     replica_count: u8           Number of physical replicas
27      1     checksum_profile_id: u8     Checksum algorithm selector
28      1     compression: u8             Compression algorithm (0 = none)
29      1     extent_flags: u8            Per-extent flags
30      8     created_commit_group: u64            Transaction group that created this entry
38     32     payload_digest: [u8; 32]    BLAKE3-256 over logical payload bytes
70      8     payload_bytes: u64          Logical payload size
78      8     on_media_bytes: u64         Physical on-media size (>= payload_bytes)
86     11     reserved: [u8; 11]          Zero-filled; TLV extension anchor
97      ?     replica_placement: Vec      Variable-length replica list
```

**Key design choices:**

- `locator_rev` increments on every `relocate` call, giving consumers a
  monotonic version to detect stale cached physical mappings.
- `payload_bytes` vs `on_media_bytes`: the ratio is the compression ratio.
  When `COMPRESSED` is not set, they are equal.
- `replica_placement` is a `Vec<ReplicaPlacement>` (variable-length), so the
  fixed-size portion is 97 bytes; the total record size depends on replica
  count, up to the page budget (4096 bytes).
- The locator entry also accommodates `replica_count = 0` for newly allocated
  entries prior to replication, and for retired entries retaining only the
  locator_id key.

### 2.3 `ReplicaPlacement` — Physical Location of One Replica

```rust
pub struct ReplicaPlacement {
    pub node_id: u64,
    pub device_id: u64,
    pub shard_placements: Vec<ShardPlacement>,
    pub health: ReplicaHealth,
}
```

A replica is a complete physical copy of the extent data on a specific device
on a specific node. For non-sharded extents, `shard_placements` contains a
single `ShardPlacement` with `shard_index = 0`. For sharded extents (when
`flags & SHARDED`), multiple `ShardPlacement` entries partition the logical
extent across shards.

### 2.4 `ShardPlacement` — Grain-Span Sub-location

```rust
pub struct ShardPlacement {
    pub shard_index: u16,
    pub segment_id: u64,
    pub grain_offset: u64,
    pub grain_count: u64,
}
```

Each shard placement maps one logical shard to a contiguous grain range within
a segment. The sum of `grain_count` across all shards in a replica equals the
total grains allocated to that replica.

### 2.5 `ReplicaHealth` — Per-Replica State

```rust
pub enum ReplicaHealth {
    Online = 0,
    Degraded = 1,
    Offline = 2,
    Retired = 3,
    Corrupt = 4,
}
```

| State | Readable | Description |
|-------|----------|-------------|
| `Online` | Yes | Normal operation; data is accessible and verified |
| `Degraded` | Yes | Accessible but at risk (e.g., one mirror leg failed) |
| `Offline` | No | Device or node unreachable |
| `Retired` | No | Permanently decommissioned; data freed or migrated |
| `Corrupt` | No | Integrity check failed; replica cannot be trusted |

The `is_readable()` predicate returns `true` only for `Online` and `Degraded`.
Consumers (the read path) must select a readable replica or return `EIO`.

### 2.6 Locator Flags

Defined in `tidefs-types-locator-table-core::locator_flags`:

| Flag | Bit | Meaning |
|------|-----|---------|
| `SHARDED` | 0 | Extent is split across shards; see `shard_placements` |
| `ERASURE_CODED` | 1 | Extent uses erasure coding instead of replication |
| `COMPRESSED` | 2 | `on_media_bytes < payload_bytes`; decompress on read |
| `ENCRYPTED` | 3 | Payload is encrypted at rest |
| `DEDUP_ELIGIBLE` | 4 | Extent may share payload with other locators |
| `CLONE_TARGET` | 5 | Extent is a reflink clone target (shared payload) |
| `DEADLIST` | 6 | Locator is on the deadlist (pending async reclamation) |
| `INLINE_PAYLOAD` | 7 | Payload is embedded in the locator value (tiny extents) |

### 2.7 `V1LocatorTable` — The Inline-Hash Engine

```rust
pub struct V1LocatorTable {
    pub next_id: u64,                                 // next free LocatorId
    pub entries: BTreeMap<LocatorId, ExtentLocatorValueV1>,  // active locators
    pub alloc_count: u64,                             // total allocations
}
```

**Key properties:**

- **Monotonic `next_id`**: starts at 1, never decrements. A `LocatorId` is
  never reused. This guarantees that a stale `LocatorId` held by an old extent
  map entry will always produce `NotFound` rather than silently resolving to
  a different extent.
- **`BTreeMap` storage**: O(log n) lookup, insert, delete. The in-memory map
  is the single source of truth for the V1 representation; there is no on-disk
  persistence in V1. Crash recovery requires locator table rebuild from the
  commit_group commit log (deferred to V2).
- **`alloc_count`**: tracks total `allocate()` calls for generation tracking
  and observability.

## 3. The `LocatorTableOps` Trait

All locator table engines (V1, V2) implement this trait, defined in
`tidefs-types-locator-table-core`:

| Method | Purpose |
|--------|---------|
| `resolve(locator_id)` | Look up physical replicas for a locator |
| `allocate(payload_bytes, digest, replicas, commit_group)` | Allocate a new locator with replicas |
| `relocate(old_id, new_replicas)` | Atomically update replica placement |
| `retire(locator_id)` | Mark all replicas as `Retired` |
| `batch_resolve(locator_ids)` | Resolve multiple locators in one call |

### 3.1 `resolve`

```
resolve(LocatorId) -> Result<ExtentLocatorValueV1, LocatorTableError>
```

Lookup algorithm:
1. Reject `LocatorId::NONE` → `InvalidLocatorId`.
2. Look up `self.entries.get(&locator_id)`.
3. Return `NotFound` if absent; clone and return the value otherwise.

O(log n) via `BTreeMap::get`. The clone cost is acceptable for the single-locator
read path (a typical I/O resolves 1–4 locators per operation).

### 3.2 `allocate`

```
allocate(payload_bytes, payload_digest, replica_placement, created_commit_group)
    -> Result<ExtentLocatorValueV1, LocatorTableError>
```

Allocation algorithm:
1. Reject `payload_bytes == 0` → `AllocationFailed`.
2. Reject empty `replica_placement` → `AllocationFailed`.
3. Assign `id = LocatorId(self.next_id)`.
4. Construct `ExtentLocatorValueV1::new(id, 0, created_commit_group, digest, payload_bytes)`.
5. Add each `ReplicaPlacement` via `entry.add_replica(rp)`.
6. Compute `on_media_bytes = sum(replica.total_grains())`.
7. Increment `next_id` and `alloc_count`.
8. Insert into `entries` and return the entry.

O(log n). The caller (typically the extent map layer) is responsible for
actually writing data to the allocated grains before committing the commit_group.

### 3.3 `relocate`

```
relocate(old_locator_id, new_replica_placement)
    -> Result<ExtentLocatorValueV1, LocatorTableError>
```

Relocation algorithm:
1. Reject `LocatorId::NONE` → `InvalidLocatorId`.
2. Reject empty `new_replica_placement` → `AllocationFailed`.
3. Look up existing entry → `NotFound` if absent.
4. If `existing.replica_placement == new_replica_placement` → return
   `RelocationNoop` (idempotency guard, prevents unnecessary revision bumps).
5. Increment `existing.locator_rev`.
6. Replace `replica_placement` and recompute `replica_count` and
   `on_media_bytes`.
7. Return the updated entry clone.

O(log n). Relocation preserves the `LocatorId` — extent maps are unaffected.
This is the critical advantage of physical indirection.

### 3.4 `retire`

```
retire(locator_id) -> Result<(), LocatorTableError>
```

Retirement algorithm:
1. Reject `LocatorId::NONE` → `InvalidLocatorId`.
2. Look up existing entry → `NotFound` if absent.
3. Set every replica's `health` to `Retired`.
4. The locator entry remains in the table (with `replica_count` preserved)
   for auditability. Physical space reclamation is handled by the refcount
   delta cleanup queue (#1180).

O(log n). Retirement is idempotent: retiring an already-retired locator
succeeds silently.

### 3.5 `batch_resolve`

```
batch_resolve(&[LocatorId]) -> Vec<(LocatorId, ExtentLocatorValueV1)>
```

Batch algorithm:
1. For each `LocatorId` in the input:
   - Skip `NONE` ids.
   - Look up in `entries`; include in output if found, skip silently if not.
2. Return the collected vector.

O(k × log n) where k is the batch size. The silent-skip semantics for
not-found locators avoids error-path complexity in batch read-ahead and
prefetch paths.

## 4. Replica Lifecycle and Health Tracking

### 4.1 State Machine

```
      ┌──────────┐
      │  Online  │ ◄── initial state after allocation
      └────┬─────┘
           │ device/node failure detected
           ▼
      ┌──────────┐
      │ Degraded │ ◄── still readable; repair may restore
      └────┬─────┘
           │ second failure OR prolonged outage
           ▼
      ┌──────────┐
      │ Offline  │ ◄── not readable; must use another replica
      └────┬─────┘
           │ device recovered
           ▼
      ┌──────────┐
      │  Online  │ ◄── restored by resilver/rebuild
      └──────────┘

                    ┌────────────────┐
                    │ Online/Degraded│
                    └───────┬────────┘
                            │ explicit retire() call
                            ▼
                    ┌──────────┐
                    │ Retired  │ ◄── terminal state; space freed via reclaim
                    └──────────┘

      ┌──────────┐
      │  Any     │ ◄── integrity check failure
      └────┬─────┘
           ▼
      ┌──────────┐
      │ Corrupt  │ ◄── not readable; must repair from another replica
      └──────────┘
```

### 4.2 Replica Count Guarantees

- `replica_count` is derived from `replica_placement.len()`.
- The write path must ensure at least `min_redundancy` replicas are `Online`
  before acknowledging a write.
- The read path selects the first `Online` replica; if none are `Online`, it
  falls back to `Degraded`. If none are readable, it returns `EIO`.

## 5. Error Model

`LocatorTableError` enumerates all failure modes:

| Variant | Trigger | Recovery |
|---------|---------|----------|
| `NotFound` | `LocatorId` not in table | Caller may retry or report `ESTALE` |
| `InvalidLocatorId` | `LocatorId::NONE` passed | Caller bug; fix the call site |
| `Corrupt` | Key-value mismatch or id invariant violated | Rebuild from commit_group log (V2) |
| `WrongSchemaVersion` | Unsupported schema (V2 deferred) | Upgrade on-media format |
| `AllocationFailed` | Zero payload or empty replicas | Caller bug; fix the call site |
| `RelocationNoop` | Relocate to same placement | Harmless; caller may skip |
| `RefcountUnderflow` | Reclaim refcount went below zero | Integrity error; halt reclaim |
| `StillReferenced` | Attempt to retire locator with active refs | Caller bug; fix the call site |



1. **No NONE ids**: no entry key may be `LocatorId(0)`.
2. **Key-value consistency**: every entry's `val.locator_id` must equal the
   `BTreeMap` key.
3. **ID < next_id**: every key's `0 < key.0 < self.next_id`.

These invariants catch corruption of the in-memory map. In V1, there is no
on-media page to checksum; in V2, each B-tree page will carry a BLAKE3-256
checksum covering the page header and all entries.

## 7. Integration Points

### 7.1 With Extent Maps

Every `ExtentMapEntryV2` with `extent_kind = DATA` stores a `locator_id: [u8; 16]`
(zero-padded u64). When the read path encounters a DATA entry:

1. Decode `locator_id` from the 16-byte field.
2. Call `locator_table.resolve(locator_id)`.
3. Select a readable replica from `replica_placement`.
4. Issue I/O to `(node_id, device_id, grain_offset, grain_count)`.

When the write path allocates a new extent:

1. The allocator returns `(device_id, grain_offset, grain_count)`.
2. `locator_table.allocate(...)` creates the locator entry.
3. The returned `LocatorId` is stored in the new `ExtentMapEntryV2`.
4. Data is written to the allocated grains.
5. The commit_group commits both the extent map and locator table atomically.

### 7.2 With COMMIT_GROUP State Machine

The V1 locator table is in-memory only. On crash:

1. The commit_group commit log is replayed to rebuild the locator table.
2. Each committed commit_group contains the `allocate`/`relocate`/`retire` operations
   needed for reconstruction.
3. In V2, locator table pages will be flushed as part of commit_group sync, providing
   persistent recovery without full log replay.

### 7.3 With Spacemap Allocator (#1127)

`allocate` consumes grains from the spacemap. The `on_media_bytes` field is
computed as `sum(replica.total_grains())`, which must match the allocator's
returned grain count. The allocator is the authoritative source for physical
space; the locator table records the mapping.

### 7.4 With Refcount Delta Cleanup Queues (#1180)

When all extent map entries referencing a `LocatorId` are freed:

1. The refcount reaches zero.
2. The locator is added to the deadlist (`DEADLIST` flag set).
3. The reclaim queue processes deadlist entries asynchronously.
4. Physical space is returned to the spacemap allocator.
5. The locator entry is retired (all replicas marked `Retired`).

### 7.5 With Dataset Feature Flags (#1223)

The `org.tidefs:locator_table` feature flag gates locator table usage:

| Flag State | Behavior |
|------------|----------|
| `DISABLED` | Legacy chunk-manifest model; locator table not used |
| `ENABLED` | Extent maps use locator table for DATA entries |
| `ENABLED_ACTIVE` | All datasets actively use locator table; legacy model deprecated |

## 8. V1 vs V2 Design Tradeoffs

| Aspect | V1 (Inline-Hash) | V2 (B-tree Page, deferred) |
|--------|-----------------|---------------------------|
| Storage | In-memory `BTreeMap` | Persistent on-media B-tree |
| Crash recovery | Full commit_group log replay | Page-level CoW with checksums |
| Scalability | ~10⁶ locators (memory-bound) | ~10⁹ locators (disk-backed) |
| Snapshot isolation | Not supported | Per-commit_group page snapshots |
| Multi-node | Single-node only | Sharded B-tree across nodes |
| Read latency | ~100 ns (hash lookup) | ~10 µs (1–2 page reads) |
| Write latency | ~100 ns (hash insert) | ~100 µs (page allocation + write) |
| Implementation complexity | ~500 lines | ~2500 lines (estimated) |
| Suitable for | Development, single-node | Production, multi-node |

### 8.1 Why V1 First

The V1 inline-hash representation provides:

- **Immediate correctness**: the full `LocatorTableOps` contract is exercised
  with a simple, auditable implementation.
  B-tree complexity is introduced.
  do not need multi-million-locator scale.
- **Gradual migration**: the `LocatorTableOps` trait allows V1 → V2 switching
  without changing any callers.

### 8.2 When to Promote to V2

V2 should be implemented when:
- On-disk persistence is required (no more commit_group log replay).
- Locator count exceeds ~500K (memory pressure).
- Multi-node clusters need distributed locator resolution.
- Snapshot isolation of locator state is required.

## 9. Implementation Status (as of 2026-05-04)

| Component | Crate | Status |
|-----------|-------|--------|
| `LocatorId`, `LocatorTableId` | `tidefs-types-extent-map-core` | Complete |
| `ExtentLocatorValueV1` (122-byte record) | `tidefs-types-locator-table-core` | Complete |
| `ReplicaPlacement`, `ShardPlacement` | `tidefs-types-locator-table-core` | Complete |
| `ReplicaHealth` (5-state enum) | `tidefs-types-locator-table-core` | Complete |
| `LocatorTableOps` trait (5 methods) | `tidefs-types-locator-table-core` | Complete |
| `LocatorTableError` (8 variants) | `tidefs-types-locator-table-core` | Complete |
| `V1LocatorTable` engine | `tidefs-locator-table` | Complete (28 tests) |

### 9.1 Future Work (Deferred to Follow-on Issues)

| Phase | Description | Depends on |
|-------|-------------|-----------|
| V2 B-tree page engine | Persistent on-media B-tree with CoW | Shard groups (#1286) |
| Locator table flush in commit_group sync | Persistent pages committed during commit_group | V2 engine |
| Distributed locator resolution | Sharded locator table across nodes | Cluster membership (#1249) |
| Locator table snapshot isolation | Per-commit_group page snapshots | V2 engine + commit_group state machine |
| Erasure-coded extent placement | Multi-shard erasure coding in `ReplicaPlacement` | #1286 |
| `DEADLIST` flag processing | Async reclamation of retired locators | #1180 |
| Production observability | Prometheus counters for locator ops | Metrics framework |

## 10. Non-claims (Explicit Boundaries)

- This design specifies the V1 inline-hash locator table. The V2 B-tree page
  engine is deferred to a successor issue.
- On-media persistence of locator table pages is deferred to V2. The V1 table
  is in-memory only.
- Distributed (multi-node) locator resolution is deferred to cluster membership
  and replication designs.
- Shard-level placement and erasure coding are specified at the interface level;
  the actual shard layout is deferred to #1286.
- Dedup integration (shared `LocatorId` across extent maps) is deferred to #1255.
- The refcount lifecycle and deadlist processing are specified by #1180; the
  locator table only provides the `DEADLIST` flag and `retire()` operation.
- Compression key management for `ENCRYPTED` locators is deferred to the
  encryption-at-rest design.

## 11. References

- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` — Canonical extent map and locator table design (#1285)
- `docs/design/v1-extent-map-tristate-model.md` — V1 extent map tristate model design spec (#1566)
- `docs/design/polymorphic-extent-maps-design.md` — Polymorphic extent map switching design (#1555)
- `crates/tidefs-types-locator-table-core/src/lib.rs` — Type definitions, constants, and `LocatorTableOps` trait
- `crates/tidefs-locator-table/src/lib.rs` — V1LocatorTable and 28 unit tests
- `crates/tidefs-types-extent-map-core/src/lib.rs` — `LocatorId`, `ExtentId`, `ExtentMapEntryV2`
- `docs/DATASET_FEATURE_FLAGS_DESIGN.md` — Dataset feature flags (#1223)
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` — Refcount cleanup queue design (#1180)

## 12. Changelog

| Date | Change | Issue |
|------|--------|-------|
