# Polymorphic Extent Maps: Inline → B-tree → Multi-level B-tree Design

Maturity: **design-spec** for three-level polymorphic extent map representation
switching, spanning inline-list for tiny files through multi-level B-tree for
TiB-scale fragmented files, with transactional promotion/demotion per commit_group.

This document closes Forgejo issue #1291.

## 1. Motivation

Extent maps face extreme scaling variance across file sizes:

| File class | Size | Typical extent count | Optimal representation |
|-----------|------|---------------------|----------------------|
| Tiny files | 0–4 KiB | 1 | Inline in inode |
| Small files | 1–100 MiB | 10–1,000 | Single B-tree |
| Huge sparse files | 100 GiB–1 TiB | 10K–100K | Single B-tree (strained) |
| Huge fragmented files | 1+ TiB | 100K–1M+ | Multi-level B-tree |

Fixed representations force either metadata bloat (B-tree for tiny files) or
RMW amplification (inline list for large files). The v0.262 design already
calls for adaptive switching between ExtentMapV1 (inline, ≤6 entries) and
ExtentMapV2 (single B-tree). This design adds ExtentMapV3 (multi-level B-tree)
and formalizes the switching policy across all three levels.

### Dependency Map

| Issue | Name | Relationship |
|-------|------|-------------|
| #1285 | Extent maps and locator tables | Canonical extent map format, `ExtentMapEntryV2`, `ExtentMapOps` trait |
| #1305 | V1 locator table | `ExtentLocatorValueV1`, `LocatorId` derivation |
| #1180 | Refcount delta cleanup queues | Extent lifecycle during migration |
| #1257 | Workload-adaptive recordsize | Recordsize influences extent count → promotion pressure |
| #1286 | Shard groups and rebake | Locator table V2 integration with shard group pointers |
| #1223 | Dataset feature flags | `org.tidefs:polymorphic_extent_maps` feature gate |
| #1179 | Background service framework | Migration as `BackgroundService` work item |

## 2. Design Overview

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

Promotion:  >6 entries → V2      >100K entries → V3
Demotion:   <4 entries → V1      <50K entries  → V2   (hysteresis applied)
```

Three canonical extent map representations share a single `ExtentMapOps` trait
and migrate transactionally within a single commit_group commit. The inode records the
active representation version; readers must handle all three formats.

## 3. Three Canonical Representations

### 3.1 Inline List (V1)

The V1 representation is already implemented in `crates/tidefs-extent-map/src/lib.rs`
as `InlineExtentMap`. Key properties:

- **Storage**: `ExtentMapV1` header + up to 6 `ExtentMapEntryV2` entries stored inline
  in the `InodeRecord` extension area. No separate B-tree pages.
- **Header size**: `ExtentMapV1` is 29 bytes (root: Option<u64>, entry_count, alloc_bytes,
  file_size, version).
- **Entry capacity**: `EXTENT_MAP_V1_MAX_ENTRIES` = 6. Covers files up to ~24 KiB at
  4 KiB extent granularity.
- **Mutation**: Full rewrite on any modification (O(n) for n ≤ 6, negligible).
- **Lookup**: Binary search within the inline vector (O(log n) for n ≤ 6).
- **Zero extra I/O**: All metadata rides with the inode — critical for tiny-file
  workloads (POSIX `ls -l`, web server static assets).

### 3.2 Single B-tree (V2)

The V2 representation is already implemented in `crates/tidefs-extent-map/src/btree.rs`
as `BTreeExtentMap`. Key properties:

- **Storage**: `ExtentMapV2` header (48 bytes) in the inode, with `root_page_locator`
  pointing to the root B-tree page in the locator table.
- **B+tree**: Keyed by `logical_offset`, leaf pages hold up to 45 `ExtentMapEntryV2`
  entries. Internal nodes hold up to 45 `(separator_key, child_locator)` pairs.
- **Page size**: 4096 bytes default, configurable via `extent_map_page_size` pool property.
- **Depth**: 1 (single leaf) to 4 levels. A 4-level tree addresses ~1.6 PiB at 4 KiB
  extent granularity.
- **Mutation strategy**: Collect-then-rebuild. All entries are collected from the tree,
  the logical mutation is applied to the flat entry list, then the B+tree is rebuilt
  bottom-up. O(n) per mutation — acceptable for the V2 model where n ≤ 100K.
- **Lookup**: O(log n) via B+tree traversal.
- **CoW**: All modified pages are written to new locator table entries. Old pages are
  unreferenced via refcount decrement.

The V2 `large_file` flag (bit 0 of `ExtentMapV2.flags`) is set when the tree exceeds
4 levels, signaling that promotions to V3 should be considered.

### 3.3 Multi-level B-tree (V3)

The V3 representation is the new design contribution. It extends V2 with internal
pages that span byte-range intervals, decoupling tree fan-out from entry count.

#### 3.3.1 ExtentMapV3 Header

```rust
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtentMapV3 {
    pub root_page_locator: LocatorId,  // root internal page
    pub entry_count: u64,
    pub alloc_bytes: u64,
    pub file_size: u64,
    pub depth: u8,                     // 2-6
    pub flags: u8,                     // bit 0: migrating, bit 1-7: reserved
    pub leaf_count: u32,               // total leaf pages
    pub internal_count: u32,           // total internal pages
    pub version: u8,                   // 3
    pub reserved: [u8; 13],
}
// Total: 8 + 8 + 8 + 8 + 1 + 1 + 4 + 4 + 1 + 13 = 56 bytes
```

#### 3.3.2 V3 Internal Page

V3 internal pages use the same `ExtentMapPageHeader` (54 bytes) with `page_kind=1`,
but carry a different payload:

```
V3InternalPage {
    header: ExtentMapPageHeader,
    // entries is an array of (offset_lower_bound, child_page_locator) pairs.
    // offset_lower_bound is the minimum logical_offset in the child subtree.
    // This differs from V2 which uses separator keys.
    entries: [(u64, LocatorId); entry_count],
}
```

Each entry covers a byte-range partition: entry i maps offsets in
`[entries[i].offset_lower_bound .. entries[i+1].offset_lower_bound)`
to the subtree rooted at `entries[i].child_page_locator`.

The internal page fan-out is identical to V2: ~45 children per page.
With 6 levels (depth 6), the tree can address ~8.3 billion entries
(45^5 × 45), covering ~370 TiB at 4 KiB extent granularity with 100%
fragmentation.

#### 3.3.3 V3 Leaf Page

V3 leaf pages are identical to V2 leaf pages: `ExtentMapPageHeader` with
`page_kind=0` followed by up to 45 `ExtentMapEntryV2` entries.

#### 3.3.4 Key Design Decisions

- **Byte-range partitioning**: Internal pages partition by offset range rather
  than by dense separator keys. A TiB-scale sparse file with extents only at
  offsets 0 and 1 TiB still needs only two leaf pages (one for each extent
  cluster), not a full spanning tree. This is the critical difference from
  a naive B-tree that fills internal pages with empty separators.
- **Same page format as V2 for leaves**: Leaf pages are reusable across V2
  and V3 without conversion. Only internal pages need V3-specific handling.
- **Progressive split**: When a leaf overflows (>45 entries), it splits into
  two leaves, potentially adding an internal node. This is identical to V2
  split behavior but handled at the V3 level count.
- **Progressive merge**: When leaf underflow occurs (<12 entries), adjacent
  leaves may merge. Internal nodes are pruned when their child count drops
  below 3.

## 4. Switching Policy

### 4.1 Promotion Triggers

| Transition | Trigger | Rationale |
|-----------|---------|-----------|
| V1 → V2 | entry_count > 6 | Inline list exceeded capacity |
| V1 → V2 | Any UNWRITTEN extent present | V1 does not support UNWRITTEN |
| V1 → V2 | File has holes (gaps between entries) | V1 does not track holes efficiently |
| V2 → V3 | entry_count ≥ 100,000 (`EM_V2_V3_PROMOTION_THRESHOLD`) | Single B-tree rebuild cost exceeds budget |
| V2 → V3 | depth > 4 | Tree too deep for single-B-tree CoW overhead |
| V2 → V3 | `large_file` flag set AND entry_count ≥ 50,000 | Early promotion for known-large files |

### 4.2 Demotion Triggers (with Hysteresis)

| Transition | Trigger | Rationale |
|-----------|---------|-----------|
| V3 → V2 | entry_count < 50,000 (`EM_V3_V2_DEMOTION_THRESHOLD`) | 2× hysteresis below promotion threshold |
| V2 → V1 | entry_count ≤ 4 AND no UNWRITTEN AND no holes | 1.5× hysteresis below V1 max (6) |
| V3 → V2 | depth ≤ 2 AND entry_count < 80,000 | Shallow tree, low entry count |

Hysteresis prevents oscillation: a file hovering around 100K extents would
otherwise flip between V2 and V3 on every write. The 2× gap (100K up, 50K down)
ensures at least 50K extent changes before a demotion triggers.

### 4.3 Switching is Lazy

Switching is not eager — it is evaluated at commit_group commit time:

1. During the commit_group, all writes use the current representation.
2. At commit, `ExtentMap::commit()` checks current entry_count against thresholds.
3. If a transition is triggered, the migration is queued as a single atomic
   operation within the same commit_group.
4. The migration itself produces its own CoW pages; if it fails (e.g., ENOSPC),
   the migration is deferred to the next commit_group and the current representation
   continues to serve reads.

### 4.4 Forced Migration

`tidefsctl dataset force-extent-map-version <dataset> [v1|v2|v3]` triggers an
immediate migration. This is an admin tool for:
- Pre-upgrading known-large files during maintenance windows
- Defrag workloads where the admin knows the target representation is optimal

Forced migration generates a single commit_group that contains only the extent map
conversion — no other mutations are permitted in that commit_group.

## 5. Migration Mechanism

### 5.1 Single-COMMIT_GROUP Atomicity

Migration between representations is transactional within a single commit_group:

```
1. Allocate commit_group N
2. Read all extent entries from current representation
3. Build target representation in memory
4. Write all new pages to the locator table (new LocatorIds)
5. Update InodeRecord.extent_map to point to new representation
6. Decrement refcounts on old pages via ExtentLocatorTable::batch_decrement_refcounts()
7. Commit commit_group N
```

If any step fails (e.g., locator table full, checksum mismatch on read),
the commit_group is rolled back and the current representation remains in place.
There is no intermediate state visible to readers.

### 5.2 Refcount Safety

During migration, old pages must not be freed until the commit_group commits and
any concurrent readers have released their references. The refcount delta
cleanup queues (#1180) handle this:

- Old pages get refcount decremented in the migration commit_group.
- When refcount reaches 0, the page becomes eligible for reclamation.
- The `SegmentCleanerService` (#1286 §6) reclaims the space in a subsequent
  background tick — never synchronously in the migration commit_group.

### 5.3 Migration as BackgroundService Work Item

When a migration is triggered at commit_group commit, it is scheduled as a work item
on the `BackgroundScheduler` (#1179) at priority `Throughput` (budget stage 2).
The scheduler ensures that migration I/O does not starve latency-sensitive
foreground work.

Migration work items carry a `ValidityToken` derived from the inode's
mutation counter. If the inode is modified between scheduling and execution,
the token becomes stale and the migration is re-evaluated against the new
entry count.

### 5.4 Concurrent Readers

Readers see a consistent snapshot of the extent map for their commit_group:

- A reader at commit_group N-1 sees the old representation.
- A reader at commit_group N sees the new representation (after migration commit).
- No reader sees a partially-migrated extent map.

This is the standard CoW guarantee — the migration produces new pages with
new LocatorIds, and the commit_group commit atomically updates the inode's
`extent_map_version` and `root_page_locator`.

## 6. On-Media Format

### 6.1 Inode Extension

The `InodeRecord` carries an `extent_map_version: u8` field:

| Value | Representation | Header struct | Inline entries |
|-------|---------------|---------------|---------------|
| 0 | None (empty file) | — | — |
| 1 | ExtentMapV1 | `ExtentMapV1` (29 bytes) | Up to 6 `ExtentMapEntryV2` |
| 2 | ExtentMapV2 | `ExtentMapV2` (48 bytes) | None (in B-tree) |
| 3 | ExtentMapV3 | `ExtentMapV3` (56 bytes) | None (in B-tree) |

### 6.2 Page Format Compatibility

All three representations use the same `ExtentMapPageHeader` (4-byte magic `EXMP`,
1-byte `page_kind`, 2-byte `entry_count`, 1-byte `level`, 32-byte BLAKE3-256
checksum, 14-byte reserved). This allows:

- V2 and V3 leaf pages to be identical (page_kind=0, level=0).
- Internal pages distinguished by page_kind=1; V2 and V3 internal pages
  are differentiated by the depth field in the ExtentMap header.
  representation produced it.

### 6.3 Locator Table Integration

All B-tree pages (V2 and V3) are stored in the `ExtentLocatorTable` with
`ExtentLocatorValueV1` records. The `shard_group_ptr` field from #1286 is
populated for pages after rebake; during migration, new pages are written
as ingest extents and later rebaked.

## 7. Performance Properties

### 7.1 Metadata Overhead

| Representation | Metadata per extent | For 4 KiB extents | For 1 MiB extents |
|---------------|---------------------|-------------------|-------------------|
| V1 (inline) | 0 extra I/O | 0 | 0 |
| V2 (single B-tree) | ~1.2 pages per 45 extents | 2.7% | 0.01% |
| V3 (multi-level) | ~1.3 pages per 45 extents | 2.9% | 0.011% |

The page overhead difference between V2 and V3 is minimal (~0.2%) because
V3 only adds internal pages for indexing, not data pages. A 1 TiB file
with 256K extents (4 KiB each) has:

- V2: 5690 leaf pages (256K / 45) + ~127 internal pages = 24 MiB metadata
- V3: Same leaf pages + ~128 internal pages (2 extra levels) = 24 MiB metadata

The metadata overhead is identical to within rounding — V3's benefit is in
mutation cost, not static size.

### 7.2 Mutation Cost

| Operation | V1 (n ≤ 6) | V2 (n ≤ 100K) | V3 (n ≤ 1M) |
|-----------|-----------|---------------|-------------|
| insert_extent | O(n) rewrite, ~534 bytes | O(n) collect+rebuild, ~n × 89 bytes | O(log n) page splits, ~200 pages |
| lookup_range | O(log n) binary search | O(log n) B-tree traversal | O(log n) multi-level traversal |
| truncate | O(n) rewrite | O(n) collect+rebuild | O(log n) page splits |
| punch_hole | O(n) rewrite | O(n) collect+rebuild | O(log n) page splits + merge |

The critical win for V3 is mutation cost: inserting one extent into a 500K-extent
V2 map requires collecting and rebuilding all 500K entries (~44 MiB of in-memory
allocations). V3 performs a logarithmic traversal and splits at most O(log n) pages.

### 7.3 Read Amplification

| Query type | V1 | V2 | V3 |
|-----------|----|----|-----|
| Single 4 KiB extent lookup | 0 extra IOPs | 1–4 page reads | 2–6 page reads |
| Sequential 1 MiB read (256 × 4 KiB extents) | 0 extra IOPs | ~6 page reads | ~8 page reads |
| Random 4 KiB lookup in 1 TiB file | N/A (V1 max 24 KiB) | ~4 page reads | ~6 page reads |

The 2 extra page reads in V3 (one extra internal level) are a negligible cost
for the mutation performance win. At NVMe latencies (~100 µs), this adds ~200 µs
to a random read — invisible compared to the 4 KiB data read itself.

## 8. ZFS and Ceph Comparison

### 8.1 ZFS Indirect Block Tree

ZFS uses a fixed-depth indirect block tree with power-of-2 block pointers:

```
                    ┌────────┐
                    │  object_node  │
                    │  block_ref │──┐
                    └────────┘  │
                         ┌──────┘
                    ┌────────┐
                    │  L1    │
                    │ block_ref │──┐
                    └────────┘  │
                         ┌──────┘
                    ┌────────┐
                    │  L0    │ (≤128 KiB per block)
                    │  data  │
                    └────────┘
```

| Concern | ZFS | tidefs |
|---------|-----|--------|
| Representation | Fixed indirect block tree, unbounded depth | Polymorphic: inline for tiny, B-tree for medium, multi-level for huge |
| Tiny files | At least 1 indirect block (512–4096 bytes) + object_node | Zero extra I/O (inline in inode) |
| Mutation cost | O(log n) CoW propagation up the block tree | O(n) for V2, O(log n) for V3 |
| Block size coupling | Fixed 512B–128K recordsize, block pointer layout tied to it | Extent entries are 89 bytes regardless of extent size |
| Depth bound | Unbounded (ZFS can go 6+ levels for fragmented zvol) | V3 bounded at 6 levels (8.3 billion entries) |
| Adaptive switching | None — always indirect block tree | Automatic V1→V2→V3 with hysteresis |

ZFS pay-for-what-you-don't-need: a 4 KiB file still pays for one 128-byte
block pointer and potential indirect block reads. tidefs inline list pays
zero extra I/O for the same file.

### 8.2 Ceph ObjectExtent

Ceph stores file extents as rados objects keyed by (ino, offset):

| Concern | Ceph | tidefs |
|---------|------|--------|
| Representation | Per-object key-value in omap or leveldb | Local B-tree with deterministic page layout |
| Tiny files | Inline with inode (CephFS inline data) | Inline with inode (same approach) |
| Huge files | Rados object striping (fixed 4 MiB objects) | Multi-level B-tree pages in locator table |
| Mutation cost | Object write + omap update (2-phase commit) | Single B-tree page write (within commit_group) |
| Fragmentation | Object count explodes with small writes | Extent entries are cheap (89 bytes), pages hold 45 each |
| Read path | OSD lookup → object read | Locator table lookup → page read (one fewer hop) |

Ceph's additional OSD hop makes the random read path ~2× more expensive than
tidefs' direct locator table resolution. The multi-level B-tree provides the
same scalable namespace as Ceph's omap without requiring a distributed KV.

### 8.3 Where tidefs Improves

1. **Polymorphism**: tidefs automatically selects the optimal representation
   and adapts as the file grows/shrinks. ZFS and Ceph use single representations.
2. **Tiny-file efficiency**: Zero extra I/O for files ≤ 24 KiB — ZFS and Ceph
   both pay metadata read costs even for tiny files.
3. **Mutation cost scaling**: V3 provides O(log n) mutation for huge files
   without the fixed-depth limitation of ZFS indirect blocks.
4. **Clean separation of extent size from representation**: Extent entries are
   always 89 bytes regardless of extent size (4 KiB to 1 MiB). ZFS block pointers
   are tightly coupled to recordsize.

## 9. Integration Contracts

### 9.1 With InodeRecord (#1285)

The inode record carries `extent_map_version: u8` and either:
- `ExtentMapV1` inline (29 bytes + up to 6 entries) for version 1
- `ExtentMapV2` header (48 bytes) for version 2
- `ExtentMapV3` header (56 bytes) for version 3

The `InodeRecord` total size grows from ~256 bytes (V1) to ~312 bytes (V3 header).
This is well within the 4 KiB inode page, allowing the inode itself to remain a
single read.

### 9.2 With Locator Table (#1305)

All B-tree pages are stored as `ExtentLocatorValueV1` records. Migration
produces new pages with new `LocatorId`s derived from the page content.

### 9.3 With Refcount Tracking (#1180)

Page refcounts are tracked in the `ExtentLocatorTable`. The migration algorithm
decrements old page refcounts and increments new page refcounts within the same
commit_group. The refcount cleanup queues handle deferred reclamation.

### 9.4 With Shard Groups (#1286)

After rebake, B-tree pages carry `shard_group_ptr` in their
`ExtentLocatorValueV2` (see #1286 §3.3). The extent map itself is
unaware of shard group topology — the locator table resolves physical
placement transparently.

### 9.5 With Scrub/Repair (#1288)

The B-tree page checksums (BLAKE3-256 in `ExtentMapPageHeader`) enable
per-page integrity verification. The `ScrubService` traverses extent map
pages as part of the metadata scrub path (priority order: metadata →
system metadata → data → free space). Corrupt pages trigger repair from
the `RepairService` using shard group reconstruction.

### 9.6 With Dataset Feature Flags (#1223)

The `org.tidefs:polymorphic_extent_maps` feature flag gates V3 multi-level
B-tree availability. Datasets without this flag never promote to V3; they
cap at V2 single B-tree (limited to ~100K extents before mutation cost
becomes prohibitive). This preserves forward compatibility: old code that
doesn't understand V3 can still mount the dataset with the flag disabled.

## 10. Observability Contract

| Counter | Type | Description |
|---------|------|-------------|
| `extent_map_v1_count` | Gauge | Files currently using V1 representation |
| `extent_map_v2_count` | Gauge | Files currently using V2 representation |
| `extent_map_v3_count` | Gauge | Files currently using V3 representation |
| `extent_map_promotions_v1_v2` | Counter | V1 → V2 promotions |
| `extent_map_promotions_v2_v3` | Counter | V2 → V3 promotions |
| `extent_map_demotions_v3_v2` | Counter | V3 → V2 demotions |
| `extent_map_demotions_v2_v1` | Counter | V2 → V1 demotions |
| `extent_map_migration_pages_written` | Counter | Pages written during migration |
| `extent_map_migration_latency_us` | Histogram | Migration latency in microseconds |
| `extent_map_page_split_count` | Counter | Leaf/internal page splits |
| `extent_map_page_merge_count` | Counter | Leaf/internal page merges |

## 11. Implementation Strategy

### 11.1 Phases

| Phase | Scope | Deliverable |
|-------|-------|------------|
| 1 | `ExtentMapV3` types in `tidefs-types-extent-map-core` | `ExtentMapV3`, V3 constants |
| 2 | `MultiLevelBTreeExtentMap` implementing `ExtentMapOps` | `crates/tidefs-extent-map/src/multi_level.rs` |
| 3 | Switching policy evaluation at commit_group commit | `extent_map::check_promotion_demotion()` |
| 4 | V2 ↔ V3 migration algorithm | `extent_map::migrate_v2_to_v3()` and inverse |
| 5 | InodeRecord extent_map_version=3 support | `InodeRecord` extension |
| 6 | Locator table V3 page integration | Page write/read with V3 depth tracking |
| 7 | `org.tidefs:polymorphic_extent_maps` feature flag | Dataset feature flag wiring |
| 8 | Observability counters and histograms | Prometheus metrics |
| 9 | `tidefsctl dataset force-extent-map-version` | Admin tooling |

### 11.2 Crate Boundaries

```
tidefs-types-extent-map-core/         # ExtentMapV3, constants (no_std)
tidefs-extent-map/                    # InlineExtentMap, BTreeExtentMap, MultiLevelBTreeExtentMap
  src/lib.rs                          # V1 InlineExtentMap (existing)
  src/btree.rs                        # V2 BTreeExtentMap (existing)
  src/multi_level.rs                  # V3 MultiLevelBTreeExtentMap (new)
  src/migration.rs                    # V1↔V2↔V3 migration algorithms (new)
  src/switching.rs                    # Promotion/demotion evaluation (new)
tidefs-inode/                         # InodeRecord with extent_map_version=3
tidefs-locator-table/                 # V3-depth page read/write
tidefs-xtask/                         # check-polymorphic-extent-maps
```

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `EXTENT_MAP_V1_MAX_ENTRIES` | 6 | Max entries in V1 inline list |
| `EXTENT_MAP_V2_V3_PROMOTION_THRESHOLD` | 100,000 | Entry count triggering V2 → V3 |
| `EXTENT_MAP_V3_V2_DEMOTION_THRESHOLD` | 50,000 | Entry count triggering V3 → V2 |
| `EXTENT_MAP_V2_V1_DEMOTION_THRESHOLD` | 4 | Entry count triggering V2 → V1 |
| `EXTENT_MAP_V3_MAX_DEPTH` | 6 | Maximum V3 tree depth |
| `EXTENT_MAP_PAGE_MIN_ENTRIES` | 12 | Minimum entries before leaf merge consideration |
| `EXTENT_MAP_INTERNAL_MIN_CHILDREN` | 3 | Minimum children before internal node prune |
| `EXTENT_MAP_MIGRATION_MAX_PAGES_PER_COMMIT_GROUP` | 10,000 | Max pages written in one migration commit_group |
| `EXTENT_MAP_PROMOTION_COOLDOWN_COMMIT_GROUPS` | 10 | Min commit_groups between promotion evaluations |

## 13. Error Hierarchy

```rust
pub enum PolymorphicExtentMapError {
    /// Migration target representation is the same as current.
    AlreadyAtTarget { current: u8, requested: u8 },

    /// Migration would exceed the per-commit_group page budget.
    MigrationTooLarge { pages_needed: u64, budget: u64 },

    /// Feature flag not enabled for V3 promotion.
    V3NotEnabled,

    /// Migration read encountered a corrupt page.
    SourcePageCorrupt { locator_id: LocatorId, reason: String },

    /// Migration write failed (ENOSPC, device error).
    TargetPageWriteFailed { reason: String },

    /// Refcount update during migration failed.
    RefcountUpdateFailed { locator_id: LocatorId, reason: String },
}
```

## 14. Non-claims (Explicit Boundaries)

- This design does not specify on-disk B-tree page locking for concurrent mutation
  within a single commit_group (V2 already serializes via collect-then-rebuild).
- This design does not cover extent map defragmentation as a background service;
  that is deferred to #1265 (online defrag of base shards).
- This design does not cover distributed extent map replication; single-node
  extent maps are fully specified here, and distributed extent maps will extend
  this design as a separate issue.
- The V3 multi-level B-tree does not support online page-level deduplication;
  dedup operates at the extent level (#1255).

## 15. References

- [#1285] Extent Maps and Locator Tables Design (`docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md`)
- [#1305] V1 Locator Table (`crates/tidefs-locator-table/`)
- [#1180] Refcount Delta-Based Incremental Data Cleanup Queues (`docs/REFCOUNT_DELTA_CLEANUP_QUEUES_DESIGN.md`)
- [#1286] Shard Groups, Replicas, and Rebake Pathway (`docs/SHARD_GROUPS_REPLICAS_REBAKE_DESIGN.md`)
- [#1288] Scrub, Deep Scrub, Repair, and Resilver Orchestration (`docs/SCRUB_REPAIR_RESILVER_DESIGN.md`)
- [#1223] Dataset Feature Flags Architecture (`docs/DATASET_FEATURE_FLAGS_DESIGN.md`)
- [#1179] Background Service Framework (`docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`)
- [#1265] Online Defrag of Base Shards (future)
- [#1255] Inline and Post-Process Deduplication (future)
- [#1257] Workload-Adaptive Recordsize and Extent Shaping (future)

## ZFS and Ceph Design-Mistake Coverage

- **ZFS fixed-depth indirect block tree**: ZFS always uses indirect blocks
  even for tiny files. tidefs uses inline list (zero extra I/O) for files
  ≤ 24 KiB. ZFS also has no promotion/demotion — the block tree is always
  the same structure regardless of file size.

- **ZFS recordsize coupling**: ZFS block pointer layout is tightly coupled
  to recordsize. tidefs extent entries are 89 bytes regardless of extent size.

- **Ceph omap overhead**: Ceph stores extent maps in leveldb/rocksdb omap,
  requiring a distributed KV read for every extent lookup. tidefs extent map
  pages are in the locator table with a single deterministic lookup.

- **Ceph multi-hop**: Ceph extent resolution requires OSD → PG → object
  hops. tidefs resolves `LocatorId → ExtentLocatorValueV1` in a single
  B-tree lookup within the locator table.
