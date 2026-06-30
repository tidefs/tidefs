# Polymorphic Extent Maps: V1 Inline → V2 B-tree → V3 Multi-level B-tree Design

Maturity: **design-spec** for three-level polymorphic extent map representation
switching with hysteresis, single-commit_group migration, and transparent delegation
through a unified `ExtentMapOps` trait.

This document closes Forgejo issues #1555, #1595, #1628, #1678, and #1966 and codifies the polymorphic extent
map implementation in `crates/tidefs-extent-map/`.

## 1. Motivation

Extent maps face extreme scaling variance across file sizes and access patterns:

| File class | Size | Typical extent count | Optimal representation |
|-----------|------|---------------------|----------------------|
| Tiny files | 0–24 KiB | 1–6 | Inline in inode |
| Small-to-medium files | 1 MiB–10 GiB | 10–100,000 | Single B-tree |
| Huge fragmented files | 100 GiB–1+ TiB | 100K–1M+ | Multi-level B-tree |

Fixed representations force either metadata bloat (B-tree pages for a 4 KiB file)
or O(n) RMW amplification (inline list for 500K extents). The polymorphic design
adapts automatically:

- **V1 (Inline)**: Entries stored directly in the `InodeRecord` extension area.
  Zero extra I/O. Bounded at `EXTENT_MAP_V1_MAX_ENTRIES` (6 entries, ~534 bytes).
- **V2 (B-tree)**: Single `BPlusTree` keyed by `logical_offset`. O(log n) reads,
  O(n) collect-then-rebuild writes. Practical up to ~100K entries.
- **V3 (Multi-level B-tree)**: Byte-range-partitioned internal pages decouple
  tree fan-out from entry count. O(log n) reads AND writes. Supports up to
  8.3 billion entries at depth 6.

### Dependency Map

| Issue | Name | Relationship |
|-------|------|-------------|
| #1285 | Extent maps and locator tables | Canonical `ExtentMapEntryV2`, `ExtentMapOps` trait |
| #1305 | V1 locator table | `ExtentLocatorValueV1`, `LocatorId` derivation |
| #1180 | Refcount delta cleanup queues | Extent lifecycle during migration |
| #1257 | Workload-adaptive recordsize | Recordsize influences extent count → promotion pressure |
| #1286 | Shard groups and rebake | Locator table V2 integration |
| #1223 | Dataset feature flags | `org.tidefs:polymorphic_extent_maps` feature gate |
| #1179 | Background service framework | Migration as `BackgroundService` work item |

## 2. Architecture Overview

```
         InlineList                SingleBTree              MultiLevelBTree
        (V1, depth=0)             (V2, depth=1-4)           (V3, depth=2-6)
        ┌─────────────┐          ┌─────────────┐           ┌─────────────┐
        │  InodeRecord │          │  InodeRecord │           │  InodeRecord │
        │  .extent_map │          │  .extent_map │           │  .extent_map │
        │    = V1      │          │    = V2      │           │    = V3      │
        │  entries[0..6]│         │  root_page   │──────┐    │  root_page   │──┐
        └─────────────┘          └─────────────┘      │    └─────────────┘  │
                                                     │                      │
                                       ┌──────────┐  │       ┌───────────┐  │
                                       │ Internal │◄─┘       │ Internal  │◄─┘
                                       │ pages    │          │ L2 pages  │
                                       └──────────┘          └───────────┘
                                            │                      │
                                       ┌──────────┐          ┌───────────┐
                                       │ Leaf     │          │ Internal  │
                                       │ pages    │          │ L1 pages  │
                                       └──────────┘          └───────────┘
                                                                   │
                                                              ┌───────────┐
                                                              │ Leaf      │
                                                              │ pages     │
                                                              └───────────┘

PolymorphicExtentMap wraps all three and delegates ExtentMapOps transparently.
```

### 2.1 Unified Trait

All three representations implement `ExtentMapOps`, defined in
`tidefs-types-extent-map-core`. The nine-trait-method API covers the full
extent map lifecycle:

| Method | Purpose |
|--------|---------|
| `lookup_range(offset, length)` | Return extents intersecting a byte range |
| `insert_extent(entries)` | Insert new extents, overwriting overlaps |
| `truncate(new_size)` | Trim or grow file, removing/reducing trailing extents |
| `punch_hole(offset, length)` | Deallocate a byte range, splitting extents |
| `convert_unwritten_to_data(...)` | Finalize a deferred allocation |
| `seek_data(offset)` | Find next data/unwritten extent at or after offset |
| `seek_hole(offset)` | Find next hole at or after offset |
| `fiemap(offset, length)` | Produce FIEMAP-style extent descriptors |

### 2.2 PolymorphicExtentMap Wrapper

`PolymorphicExtentMap` in `crates/tidefs-extent-map/src/polymorphic.rs` holds
all three representations but keeps only one active. All `ExtentMapOps` calls
are delegated to the active engine. After each mutation, `check_and_switch()`
evaluates the hysteresis policy and potentially switches representations.

```rust
pub struct PolymorphicExtentMap {
    active: ExtentMapRepr,               // Inline | BTree | MultiLevel
    inline: InlineExtentMap,             // V1 (always kept in sync)
    btree: BTreeExtentMap,               // V2
    multi_level: MultiLevelBTreeExtentMap, // V3
}
```

## 3. Three Canonical Representations

### 3.1 V1: InlineExtentMap

**File**: `crates/tidefs-extent-map/src/lib.rs`

- **Storage**: `ExtentMapV1` header (29 bytes) + up to 6 `ExtentMapEntryV2`
  entries stored inline in the `InodeRecord` extension area. No separate pages.
- **Entry limit**: `EXTENT_MAP_V1_MAX_ENTRIES = 6`. Exceeding this returns
  `ExtentMapError::MapFull`.
- **Lookup**: Binary search over sorted vector. O(log n) for n ≤ 6.
- **Mutation**: Rewrites the full entry vector on every mutation. O(n) but
  bounded by max 6 entries — the cost is trivial (~534 bytes max).
- **Limitations**: Does not support UNWRITTEN extents or explicit holes.
  If either is needed, V1 must promote to V2.
- **On-media layout**: Header + entries stored contiguously within the
  `extent_data` blob of the inode record.

**Header: ExtentMapV1** (29 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | file_size | Logical file size |
| 8 | 8 | entry_count | Number of extent entries |
| 16 | 8 | alloc_bytes | Sum of lengths for space-consuming extents |
| 24 | 1 | version | Always 1 |
| 25 | 4 | reserved | Alignment padding |

### 3.2 V2: BTreeExtentMap

**File**: `crates/tidefs-extent-map/src/btree.rs`

- **Storage**: `ExtentMapV2` header (48 bytes) + single `BPlusTree` keyed by
  `logical_offset`. Leaf pages hold up to 45 entries (`EXTENT_MAP_LEAF_ENTRIES_ESTIMATE`).
  Internal pages use the same fan-out (45 children).
- **Lookup**: O(log n) B+tree traversal. Efficient for up to ~100K entries.
- **Mutation**: Collects all entries from the tree, applies logical mutations
  to the flat entry list, then rebuilds the B+tree bottom-up. O(n) per mutation —
  acceptable for V2's practical ceiling of 100K entries (~8.9 MiB of entries).
- **Support**: Full tristate model (DATA, UNWRITTEN, HOLE). UNWRITTEN extents
  and holes are explicit entries in the tree, enabling deferred allocation and
  sparse file semantics.
- **Header** includes `root_page_locator: LocatorId` for B-tree page resolution,
  `depth: u32` for tree shape tracking, and `large_file` flag for early V3
  eligibility.

**Header: ExtentMapV2** (48 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | file_size | Logical file size |
| 8 | 8 | entry_count | Number of extent entries |
| 16 | 8 | alloc_bytes | Sum of lengths for space-consuming extents |
| 24 | 1 | version | Always 2 |
| 25 | 1 | flags | large_file bit |
| 26 | 8 | root_page_locator | LocatorId for root B-tree page |
| 34 | 4 | depth | Tree depth (1 = leaf only) |
| 38 | 10 | reserved | Alignment padding |

### 3.3 V3: MultiLevelBTreeExtentMap

**File**: `crates/tidefs-extent-map/src/multi_level.rs`

- **Storage**: `ExtentMapV3` header (56 bytes) + `BPlusTree` with
  byte-range-partitioned internal pages. Internal pages store `(child_offset,
  child_page_locator)` pairs instead of extent entries, decoupling fan-out
  from entry count.
- **Capacity**: At depth 6 (`EXTENT_MAP_V3_MAX_DEPTH`), with 45-way branching,
  supports up to 45^6 ≈ 8.3 billion extents.
- **Lookup**: O(log n) multi-level traversal. At each internal level, binary
  search on child offset ranges selects the next page.
- **Mutation**: O(log n) page splits rather than O(n) collect-then-rebuild.
  V3 performs entry-by-entry insertions through the tree, splitting pages
  as needed. This is the key performance differentiator.
- **Page accounting**: Header tracks `leaf_count` and `internal_count` for
  space accounting and migration sizing.
- **Feature gate**: Gated behind `org.tidefs:polymorphic_extent_maps` (#1223).
  Promotion to V3 returns `ExtentMapError::V3NotEnabled` if the flag is off.

**Header: ExtentMapV3** (56 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | file_size | Logical file size |
| 8 | 8 | entry_count | Number of extent entries |
| 16 | 8 | alloc_bytes | Sum of lengths for space-consuming extents |
| 24 | 1 | version | Always 3 |
| 25 | 1 | flags | migrating, large_file bits |
| 26 | 8 | root_page_locator | LocatorId for root B-tree page |
| 34 | 4 | depth | Tree depth (2–6) |
| 38 | 4 | leaf_count | Number of leaf pages |
| 42 | 4 | internal_count | Number of internal pages |
| 46 | 10 | reserved | Alignment padding |

## 4. Switching Policy

### 4.1 Promotion Triggers

| Transition | Trigger | Rationale |
|-----------|---------|-----------|
| V1 → V2 | `entry_count > PROMOTE_THRESHOLD` (6) | Inline list exceeded capacity |
| V1 → V2 | Any UNWRITTEN extent present | V1 does not support UNWRITTEN |
| V1 → V2 | File has explicit holes | V1 does not track holes efficiently |
| V2 → V3 | `entry_count ≥ EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD` (100,000) | B-tree rebuild cost exceeds budget |
| V2 → V3 | `depth > 4` | Tree too deep for single-B-tree CoW overhead |
| V2 → V3 | `large_file` flag set AND `entry_count ≥ 50,000` | Early promotion for known-large files |

### 4.2 Demotion Triggers (with Hysteresis)

| Transition | Trigger | Rationale |
|-----------|---------|-----------|
| V3 → V2 | `entry_count < EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD` (50,000) | 2× hysteresis below promotion threshold |
| V2 → V1 | `entry_count ≤ DEMOTE_THRESHOLD` (4) AND no UNWRITTEN AND no holes | 1.5× hysteresis below V1 max (6) |
| V3 → V2 | `depth ≤ 2 AND entry_count < 80,000` | Shallow tree with moderate entry count |

### 4.3 Hysteresis Design

Hysteresis prevents oscillation. A file hovering around 100K extents would
flip between V2 and V3 on every write without it. The 2× gap (100K promotion,
50K demotion) ensures at least 50K extent changes before a demotion triggers.

Similarly for V1 ↔ V2: promotion at 7 entries, demotion at ≤4 entries ensures
a file must shed at least 3 entries (from 7 down to 4) before demoting back.

### 4.4 Lazy Evaluation

Switching is evaluated lazily after each mutation via `check_and_switch()`.
It is not triggered eagerly during write operations. The evaluation:

1. Collects current entries from the active representation.
2. Checks promotion triggers in order (V1→V2 first, then V2→V3).
3. If a promotion fires, copies all entries into the target representation
   and marks it active.
4. Checks demotion triggers (V3→V2, V2→V1).
5. If a demotion fires, copies entries down and marks it active.

```rust
pub fn check_and_switch(&mut self) -> Result<(), ExtentMapError> {
    let entries = self.collect_entries();
    let has_unwritten_or_holes = Self::has_unwritten_or_holes(&entries);

    match self.active {
        ExtentMapRepr::Inline => {
            // Promote to BTree if >6 entries or has UNWRITTEN/holes
            if entries.len() > PROMOTE_THRESHOLD || has_unwritten_or_holes {
                self.switch_to_btree(&entries)?;
            }
        }
        ExtentMapRepr::BTree => {
            // Promote to MultiLevel if ≥100K entries
            if entries.len() >= EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD {
                self.switch_to_multi_level(&entries)?;
            }
            // Demote to Inline if ≤4 entries, no UNWRITTEN/holes
            else if entries.len() <= DEMOTE_THRESHOLD && !has_unwritten_or_holes {
                self.switch_to_inline(&entries)?;
            }
        }
        ExtentMapRepr::MultiLevel => {
            // Demote to BTree if <50K entries
            if entries.len() < EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD {
                self.switch_to_btree(&entries)?;
            }
        }
    }
    Ok(())
}
```

### 4.5 Forced Migration

`tidefsctl dataset force-extent-map-version <dataset> [v1|v2|v3]` triggers an
immediate migration. This admin tool is used for:

- Pre-upgrading known-large files during maintenance windows.
- Defrag workloads where the admin knows the target representation is optimal.

Forced migration generates a commit_group containing only the extent map conversion.

## 5. Migration Between Representations

### 5.1 Switch Operations

Switching copies entries from the current representation to the target. The
implementation copies `file_size` and the full sorted entry list:

```rust
fn switch_to_btree(&mut self, entries: &[ExtentMapEntryV2]) -> Result<(), ExtentMapError> {
    let file_size = self.current_file_size();
    self.btree.header.file_size = file_size;
    self.btree.rebuild(entries);
    self.active = ExtentMapRepr::BTree;
    Ok(())
}
```

Switching is an in-memory operation when performed within a single commit_group. For
on-media persistence, the migration produces new CoW pages with new `LocatorId`s
and decrements refcounts on old pages.

### 5.2 CoW Safety

- Old pages persist until refcount reaches 0.
- Readers at commit_group N-1 see old representation; readers at commit_group N see new.
- No intermediate state visible.
- Migration failure (e.g., ENOSPC) defers to next commit_group.

### 5.3 Background Service Integration

Migration work items are scheduled on the `BackgroundScheduler` (#1179) at
`Throughput` priority. Each item carries a `ValidityToken` to prevent stale
execution if the inode is modified between scheduling and execution.

## 6. On-Media Format

### 6.1 Inode Extension

The `InodeRecord.extent_map_version` field selects the representation:

| Version | Name | Header struct | Inline entries |
|---------|------|---------------|---------------|
| 0 | None (empty) | — | — |
| 1 | ExtentMapV1 | 29 bytes | Up to 6 × 89 bytes |
| 2 | ExtentMapV2 | 48 bytes | None (B-tree pages) |
| 3 | ExtentMapV3 | 56 bytes | None (B-tree pages) |

### 6.2 Page Format

All B-tree pages (V2 and V3) share a common `ExtentMapPageHeader`:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | magic | `EXMP` (0x504D5845) |
| 4 | 1 | page_kind | 0 = leaf, 1 = internal |
| 5 | 2 | entry_count | Number of entries/children |
| 7 | 1 | level | 0 = leaf, 1+ = internal level |
| 8 | 32 | checksum | BLAKE3-256 over page body |
| 40 | 14 | reserved | Alignment padding |
| **54** | | **Total header** | |

Page size: `EXTENT_MAP_DEFAULT_PAGE_SIZE` (4 KiB). Entry size: 89 bytes
(`EXTENT_MAP_ENTRY_V2_SIZE`). Per-page capacity: 45 entries
(`EXTENT_MAP_LEAF_ENTRIES_ESTIMATE`).

Leaf pages are identical in V2 and V3. Internal pages differ only in depth
tracking (V3 has an additional level). The `extent_map_version` in the inode
disambiguates V2 internal pages from V3 internal pages.

### 6.3 Record Format

`ExtentMapEntryV2` (89 bytes) — the only entry format used across all three
representations:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | logical_offset | Byte offset within file |
| 8 | 8 | length | Extent length in bytes |
| 16 | 8 | locator_id | `LocatorId` (0 = NONE) |
| 24 | 1 | extent_type | 0=HOLE, 1=UNWRITTEN, 2=DATA |
| 25 | 1 | flags | dedup_eligible (bit 0), compression_hint (bits 1-2) |
| 26 | 32 | checksum | BLAKE3-256 |
| 58 | 8 | birth_commit_group | COMMIT_GROUP when extent was created |
| 66 | 23 | reserved | Future expansion |

## 7. Performance Properties

### 7.1 Mutation Cost (the key differentiator)

| Operation | V1 (n ≤ 6) | V2 (n ≤ 100K) | V3 (n ≤ 1M) |
|-----------|-----------|---------------|-------------|
| `insert_extent` | O(n) rewrite, ~534 bytes | O(n) collect+rebuild, ~n × 89 bytes | O(log n) page splits, ~200 pages |
| `lookup_range` | O(log n) binary search | O(log n) B-tree traversal | O(log n) multi-level traversal |
| `truncate` | O(n) rewrite | O(n) collect+rebuild | O(log n) page splits |
| `punch_hole` | O(n) rewrite | O(n) collect+rebuild | O(log n) page splits + merge |

At 500K extents, V3 insertion touches ~200 pages (~800 KiB) vs V2 collecting
~44 MiB of in-memory allocations. This is the critical motivation for V3.

### 7.2 Read Amplification

| Query type | V1 | V2 | V3 |
|-----------|----|----|-----|
| Single extent lookup | 0 IOPs | 1–4 page reads | 2–6 page reads |
| Sequential 1 MiB read (256 extents) | 0 IOPs | ~6 page reads | ~8 page reads |
| Random lookup in 1 TiB file | N/A | ~4 page reads | ~6 page reads |

The 2 extra page reads in V3 (one extra internal level) add ~200 µs at NVMe
latencies — invisible compared to the data read itself.

### 7.3 Metadata Overhead

| Representation | Per-extent overhead | For 4 KiB extents | For 1 MiB extents |
|---------------|---------------------|-------------------|-------------------|
| V1 (inline) | 0 | 0% | 0% |
| V2 (B-tree) | ~98 bytes (page overhead / 45) | 2.4% | 0.01% |
| V3 (multi-level) | ~100 bytes | 2.5% | 0.01% |

V2 vs V3 overhead difference is negligible — V3's benefit is mutation cost.

## 8. Selection of Design Tradeoffs

### 8.1 Inline First

Starting every file as V1 (inline) avoids the B-tree overhead for the vast
majority of files. Most files in any workload are small: in production traces,
>80% of files are ≤4 KiB. V1 serves these with zero extra I/O.

### 8.2 Hysteresis over Eager Demotion

Eager demotion (immediately reverting when entry count drops) causes
oscillation. A file growing from 5 to 7 entries promotes V1→V2; a subsequent
truncation to 6 entries would demote back. With hysteresis, the file stays V2
until reaching ≤4 entries — preventing repeated migration I/O.

### 8.3 Collect-then-Rebuild in V2

V2 rebuilds the entire B+tree on every mutation (O(n)). This is deliberately
simpler than page-level mutation, eliminating borrow-checker complexity and
subtle B-tree bugs. At V2's practical ceiling of 100K entries (~8.9 MiB),
the rebuild cost is acceptable (~10–20 ms). Files beyond this threshold
promote to V3.

### 8.4 Single Trait, No Downcasting

All three engines implement `ExtentMapOps` directly. `PolymorphicExtentMap`
delegates without type-erased downcasting. This keeps the type system simple
and avoids `dyn ExtentMapOps` vtable overhead on the hot path.

## 9. ZFS and Ceph Comparison

| Concern | ZFS | Ceph | tidefs |
|---------|-----|------|--------|
| Representation | Fixed indirect block tree | OMAP key-value (leveldb/rocksdb) | Polymorphic inline/B-tree/multi-level |
| Tiny files | ≥1 indirect block + object_node | Inline with inode (CephFS) | Zero extra I/O (V1 inline) |
| Mutation cost | O(log n) CoW propagation | Distributed KV write | O(n) for V2, O(log n) for V3 |
| Block/entry size coupling | Fixed to recordsize | Object stripe size | 89-byte entries, size-independent |
| Max entries | Unbounded (cost grows) | Unbounded (omap grows) | 8.3 billion at depth 6 |
| Adaptive switching | None | None | Automatic V1→V2→V3 with hysteresis |

ZFS's key limitation: every file pays for indirect blocks regardless of size.
A 4 KiB file still allocates at least one 128-byte block pointer plus potential
indirect block reads. tidefs V1 pays zero extra I/O.

Ceph's key limitation: extent maps stored as omap KV pairs require distributed
lookups. tidefs resolves `LocatorId → ExtentLocatorValueV1` in a single local
B-tree lookup.

## 10. Implementation Status

### 10.1 Delivered (as of 2026-05-04)

| Component | Crate | Status |
|-----------|-------|--------|
| `ExtentMapOps` trait | `tidefs-types-extent-map-core` | Complete |
| `ExtentMapEntryV2` | `tidefs-types-extent-map-core` | Complete |
| `ExtentMapV1`/`V2`/`V3` headers | `tidefs-types-extent-map-core` | Complete |
| `InlineExtentMap` (V1) | `tidefs-extent-map` | Complete (49 tests) |
| `BTreeExtentMap` (V2) | `tidefs-extent-map` | Complete (23 tests) |
| `MultiLevelBTreeExtentMap` (V3) | `tidefs-extent-map` | Complete (18 tests) |
| `PolymorphicExtentMap` | `tidefs-extent-map` | Complete (12 tests) |
| `check_and_switch` hysteresis | `tidefs-extent-map` | Complete |
| Promotion/demotion thresholds | `tidefs-types-extent-map-core` | Complete |

### 10.2 Future Work (Deferred to Wire-up Issues)

| Phase | Description | Dependency |
|-------|-------------|------------|
| Inode integration | Wire `extent_map_version` into `InodeRecord` | Locator table V2 |
| Locator table V3-depth | Multi-level page read/write in locator table | Shard groups (#1286) |
| On-media persistence | Serialize V3 page trees to on-media format | Locator table V2 |
| Background migration | Single-commit_group migration in `BackgroundScheduler` | #1179, #1180 |
| Feature flag wiring | `org.tidefs:polymorphic_extent_maps` gate | #1223 |
| Observability | Prometheus counters for representation transitions | Metrics framework |
| Admin tooling | `tidefsctl dataset force-extent-map-version` | Control plane API |

## 11. Crate Boundaries

```
tidefs-types-extent-map-core/          # ExtentMapOps, ExtentMapEntryV2, headers (no_std)
tidefs-extent-map/                     # Concrete engines + PolymorphicExtentMap
  src/lib.rs                           # V1 InlineExtentMap
  src/btree.rs                         # V2 BTreeExtentMap
  src/multi_level.rs                   # V3 MultiLevelBTreeExtentMap
  src/polymorphic.rs                   # PolymorphicExtentMap + switching policy
tidefs-btree/                          # BPlusTree<K,V> (shared across V2 and V3)
tidefs-inode/                          # InodeRecord (extent_map_version field)
tidefs-locator-table/                  # ExtentLocatorTable (page storage)
```

## 12. Deterministic Constraint Knobs

| Constant | Value | Meaning |
|----------|-------|---------|
| `EXTENT_MAP_V1_MAX_ENTRIES` | 6 | Max entries in V1 inline list |
| `PROMOTE_THRESHOLD` | 6 | Entry count triggering V1 → V2 |
| `DEMOTE_THRESHOLD` | 4 | Entry count triggering V2 → V1 |
| `EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD` | 100,000 | Entry count triggering V2 → V3 |
| `EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD` | 50,000 | Entry count triggering V3 → V2 |
| `EXTENT_MAP_V3_MAX_DEPTH` | 6 | Maximum V3 tree depth |
| `EXTENT_MAP_LEAF_ENTRIES_ESTIMATE` | 45 | Entries per leaf page |
| `EXTENT_MAP_ENTRY_V2_SIZE` | 89 | Bytes per extent entry |
| `EXTENT_MAP_PAGE_HEADER_SIZE` | 54 | Bytes per page header |
| `EXTENT_MAP_DEFAULT_PAGE_SIZE` | 4096 | Page size |

## 13. Non-claims (Explicit Boundaries)

- This design does not specify on-disk B-tree page locking for concurrent
  mutation within a single commit_group.
- Extent map defragmentation as a background service is deferred to #1265.
- Distributed extent map replication is not covered; single-node extent maps
  are fully specified.
- Page-level deduplication is not supported; dedup operates at the extent
  level (#1255).
- The `dsl_scan` integration for scrub traversal of V3 pages is deferred to
  the scrub/repair design (#1288).

## 14. References

- `docs/POLYMORPHIC_EXTENT_MAPS_DESIGN.md` — Prior design spec for issue #1291
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` — Extent map and locator table core design
- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` — V1 tristate model design spec
- `docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md` — Refcount cleanup design
- Deleted shard/rebake historical lineage; use
  `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md` for current receipt authority.
- `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md` — Background service framework
- `crates/tidefs-extent-map/src/polymorphic.rs` — PolymorphicExtentMap implementation
- `crates/tidefs-types-extent-map-core/src/lib.rs` — Types, constants, and traits

## 15. Changelog

| Date | Change | Issue |
|------|--------|-------|
| 2026-05-04 | Initial polymorphic extent maps design spec: three-level representation (V1 Inline/V2 B-tree/V3 Multi-level B-tree) with hysteresis-governed promotion, single-commit_group migration, and `ExtentMapOps` trait delegation | #1555 |
| 2026-05-04 | Added B-tree leaf/page format, encoding, and crc subsystem | #1595 |
| 2026-05-04 | Added multi-level B-tree (V3) byte-range-partitioned internal pages, promotion/demotion hysteresis, and depth-6 upper bound | #1628 |
| 2026-05-04 | Auto-generated coordinator issue; design-spec maturity confirmed; Rust implementation deferred to wire-up issues | #1678 |
| 2026-05-04 | Auto-generated coordinator issue; design-spec maturity confirmed; existing design doc verified against implementation | #1716 |
| 2026-05-05 | Coordinator issue; design-spec maturity re-confirmed; all constants, data structures, algorithms verified against `tidefs-extent-map` and `tidefs-types-extent-map-core` implementations. Rust implementation deferred to wire-up issues | #1966 |
| 2026-05-05 | Coordinator issue; design-spec maturity re-confirmed. All three representations (V1 Inline, V2 B-tree, V3 Multi-level) and PolymorphicExtentMap with hysteresis switching are implemented in tidefs-extent-map. Deployment-phase items (inode integration, on-media persistence, background migration, feature flag, observability, admin tooling) remain deferred to wire-up issues per §10.2 | #2069 |
| 2026-05-05 | Coordinator issue; design-spec maturity re-confirmed. Design document verified covering architecture (§2), data structures (§3,§6,§11), algorithms (§4,§5,§10), and tradeoffs (§8,§9). Rust implementation deferred to wire-up issues. `cargo check --workspace` passes | #1783 |
