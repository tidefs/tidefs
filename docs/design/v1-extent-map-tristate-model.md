# V1 Extent Map Tristate Model: Architecture and Implementation Design

**Coord**: [#2102](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2102) (coordination seal)

Maturity: **design-sealed** — design spec sealed as the single authoritative
reference for the HOLE/UNWRITTEN/DATA tristate extent model that bridges
the canonical tristate semantics (#1225) with the polymorphic extent map
engine implemented in `crates/tidefs-extent-map/`, covering data structures,
all three representations (V1 Inline, V2 B-tree, V3 Multi-level).

This document closes Forgejo issues #1566, #1688, #1816, #1906, and #1974.

## Coordination Seal (#2102)

This document is the canonical design specification for the V1 extent map
tristate model. The design spec is sealed as authoritative under #2102.
No further design changes are permitted. Rust implementation of tristate-model
wire-up (inode integration, FUSE adapter dispatch, FIEMAP physical resolution,
in the sealed design spec, tracked under #1877.

For issue #1906 (auto-generated coordinator issue): this document is the
design-sealed deliverable. Rust implementation of tristate-model wire-up
(inode integration, FUSE adapter dispatch, FIEMAP physical resolution,
detailed in §11.1 (Future Work).


## 1. Problem Statement

A POSIX-compliant filesystem must distinguish three byte-range states within a
regular file:

| State | Created by | Read returns | `st_blocks` | `SEEK_DATA` | `SEEK_HOLE` | FIEMAP |
|-------|-----------|-------------|-------------|-------------|-------------|--------|
| **HOLE** | `truncate` extend, `punch_hole`, EOF gap | Zero | Not counted | Skips | Reports | Not reported |
| **UNWRITTEN** | `fallocate(mode=0)`, `zero_range` on hole | Zero | Counted | Reports | Skips | `FIEMAP_EXTENT_UNWRITTEN` |
| **DATA** | `write(2)`, `convert_unwritten_to_data` | Stored bytes | Counted | Reports | Skips | Physical offset |

ZFS uses a 2-state model (allocated/not-allocated) with implicit UNWRITTEN
signalled by `DVA_ASIZE == 0`. This conflates lifetime phases and requires
complex block-pointer inspection for `SEEK_HOLE`. Ceph stores extents as
{offset,length,state} RADOS omap KV pairs — correct but distributed-lookup
heavy.

TideFS makes the three states first-class in every extent map entry and
every query path, with explicit invariants enforceable by a single

### 1.1 Dependency Map

| Issue | Name | Relationship |
|-------|------|-------------|
| #1225 | V1 extent map tristate model (spec) | Canonical three-state semantics, per-state answers, mutation rules |
| #1285 | Extent maps and locator tables | `ExtentMapOps` trait, `ExtentMapEntryV2`, page layout, `LocatorId` |
| #1291 / #1555 | Polymorphic extent maps | V1→V2→V3 switching with hysteresis; `PolymorphicExtentMap` engine |
| #1180 | Refcount delta cleanup queues | Extent lifecycle when DATA entries are freed |
| #1257 | Workload-adaptive recordsize | Recordsize influences extent fragmentation → entry count pressure |
| #1223 | Dataset feature flags | `org.tidefs:extent_map_tristate` feature gate |

## 2. Core Data Structures

### 2.1 `ExtentType` Enum

Defined in `tidefs-types-extent-map-core/src/lib.rs` as a three-variant
discriminant:

```rust
pub enum ExtentType {
    Hole = 0,
    Unwritten = 1,
    Data = 2,
}
```

Key predicates:

- `consumes_space()` → `true` for Unwritten and Data (counts toward `alloc_bytes`)
- `reads_zero()` → `true` for Hole and Unwritten (no physical read needed)
- `is_data()` → `true` only for Data

### 2.2 `ExtentMapEntryV2` — The Canonical Record (89 bytes)

The on-media and in-memory entry is `ExtentMapEntryV2` (89 bytes, verified at
compile time by `EXTENT_MAP_ENTRY_V2_SIZE`):

```
Offset  Size  Field
------  ----  -----
 0      8     logical_offset: u64       Byte offset within file
 8      8     length: u64               Bytes covered, must be > 0
16      1     extent_kind: u8           0=DATA, 1=UNWRITTEN (HOLE is implicit)
17      1     flags: u8                 Bit 0: dedup_eligible, Bits 1-2: compression_hint
18     16     locator_id: [u8; 16]      Zero for UNWRITTEN; locator-table key for DATA
34     32     checksum: [u8; 32]        BLAKE3-256 over logical byte range; zero for UNWRITTEN
66      8     birth_commit_group: u64            Transaction group that created this entry
74     15     reserved: [u8; 15]        Zero-filled; TLV extension anchor
```

**Design decision: HOLE is implicit.** Gaps between entries and bytes beyond the
last entry (up to `file_size`) are holes. This avoids allocating an 89-byte
record to represent zero-cost gaps, mirroring the approach used by ZFS, ext4,
and XFS. The tradeoff is that hole queries require edge-aware extent list
traversal rather than a simple lookup, but the entry-count boundedness (≤6 for
V1, O(log n) for V2/V3) makes this negligible.

### 2.3 Extent Map Headers (V1 / V2 / V3)

Each representation carries a version-specific header with shared fields:

| Field | V1 (`ExtentMapV1`) | V2 (`ExtentMapV2`) | V3 (`ExtentMapV3`) |
|-------|-------------------|-------------------|-------------------|
| `version` | 1 | 2 | 3 |
| `file_size` | ✓ | ✓ | ✓ |
| `entry_count` | ✓ | ✓ | ✓ |
| `alloc_bytes` | ✓ | ✓ | ✓ |
| `depth` | — | ✓ (1–4) | ✓ (2–6) |
| `root_page_locator` | — | ✓ | ✓ |
| `flags` (migrating, large_file) | — | ✓ | ✓ |

`alloc_bytes` is the authoritative source for `stat(2) st_blocks`: it sums the
`length` of every entry where `consumes_space()` is true. Entries whose
`extent_kind` is UNWRITTEN or DATA contribute; holes do not.

## 3. Representation Hierarchy and Polymorphic Switching

### 3.1 Three Representations

```
V1 InlineExtentMap            V2 BTreeExtentMap            V3 MultiLevelBTreeExtentMap
┌───────────────────┐      ┌───────────────────┐       ┌───────────────────────┐
│ Vec<EntryV2> (≤6) │      │ BPlusTree<u64,V2> │       │ Multi-level B+tree     │
│ Inline in inode   │      │ Root page via     │       │ Internal L2→L1→Leaf    │
│ Zero extra I/O    │      │ LocatorId         │       │ Pages via LocatorId     │
│ O(n≤6) all ops    │      │ O(log n) read     │       │ O(log n) read & write   │
│                   │      │ O(n) write        │       │ Depth 2–6               │
│ Up to 6 entries   │      │ Up to ~100K       │       │ Up to 8.3B entries      │
└───────────────────┘      └───────────────────┘       └───────────────────────┘
```

All three implement `ExtentMapOps` — a nine-method trait covering the full
extent-map lifecycle:

| Method | Semantic |
|--------|----------|
| `lookup_range(off, len)` | Return extents intersecting `[off, off+len)` |
| `insert_extent(entries)` | Insert/overwrite extents, merge adjacent |
| `delete_range(off, len)` | Remove extents overlapping `[off, off+len)` |
| `truncate(size)` | Drop entries past `size`; trim straddling entry |
| `punch_hole(off, len)` | Remove entries in range, creating a hole |
| `zero_range(off, len)` | Convert to UNWRITTEN or punch_hole (coalescing) |
| `convert_unwritten_to_data(...)` | Atomically replace UNWRITTEN with DATA |
| `seek_data(off)` / `seek_hole(off)` | POSIX `lseek` semantics |
| `fiemap(off, len)` | Return `FiemapExtent` list for ioctl |

### 3.2 PolymorphicExtentMap: The Switching Layer

`PolymorphicExtentMap` wraps all three representations and delegates all
`ExtentMapOps` calls to the active one. After every mutation, it evaluates
a hysteresis policy:

```
  entry_count > PROMOTE_THRESHOLD (6)           → V1 → V2
  OR any entry is Unwritten                     → V1 → V2
  entry_count > V2_V3_PROMOTE_THRESHOLD (100K)  → V2 → V3
  entry_count ≤ V3_V2_DEMOTE_THRESHOLD (50K)    → V3 → V2
  entry_count ≤ DEMOTE_THRESHOLD (4)            → V2 → V1
  AND no Unwritten entries
```

Switching collects all entries from the old representation, rebuilds in the
new, copies `file_size`, and updates `representation()`. This is a single-commit_group
operation — the old representation is discarded.

The hysteresis gap (promote at 6, demote at 4; promote at 100K, demote at 50K)
prevents thrashing when a file oscillates around the threshold.

## 4. Mutation Algebra: Range-Edit Semantics

Every mutation operation is defined in terms of its effect on the sorted,
non-overlapping entry list. The algebra is representation-agnostic: V1 applies
it on a `Vec`; V2/V3 collect entries, apply the mutation, then rebuild the
B-tree.

### 4.1 `insert_extent` (Write Path)

Given a sorted, non-overlapping entry list and a new entry `E`:

1. **Preserve left-flanking entries** — entries entirely before `E.logical_offset`
   are kept unchanged.
2. **Split left-straddling entry** — if an existing entry starts before
   `E.logical_offset` but extends into `E`'s range, truncate it at
   `E.logical_offset`.
3. **Insert `E`** — place `E` in sorted order.
4. **Trim right-straddling entry** — if an existing entry starts within
   `E`'s range but extends past `E.end_offset()`, shift its `logical_offset`
   to `E.end_offset()` and reduce `length`.
5. **Drop fully-overlapped entries** — entries entirely within `E`'s range
   are removed.
6. **Merge adjacent** — after insertion, merge consecutive entries where:
   `e1.end_offset() == e2.logical_offset` AND same `extent_type` AND same
   `locator_id` AND same `checksum`.

This is a deterministic range-edit that guarantees the invariant: every byte
in `[0, file_size)` is covered by at most one entry.

### 4.2 `punch_hole` (Deallocation)

For range `[off, off+len)`:

1. Remove entries entirely within the range.
2. Trim entries that straddle the range: the prefix before `off` and the suffix
   after `off+len` become separate entries.
3. No new hole entries are created — the gap becomes an implicit hole.
4. `alloc_bytes` decreases by the `length` of removed entries that consumed
   space.

### 4.3 `truncate` (Size Change)

- **Shrink** (`new_size < old_size`): Drop all entries with
  `logical_offset ≥ new_size`. If the last entry straddles `new_size`, trim
  its `length`. Update `file_size` and recompute `alloc_bytes`.
- **Extend** (`new_size > old_size`): Set `file_size = new_size`. The gap
  from old EOF to new EOF is an implicit hole — no entries are added.

### 4.4 `zero_range` (Zero-fill Without Writing)

For range `[off, off+len)`:

1. Merge the range into existing entries using `insert`/`split` semantics.
2. If the source range falls on a HOLE, replace it with an UNWRITTEN entry
   (allocates space, read returns zero, counts toward `st_blocks`).
3. If the source range falls on DATA, replace it with UNWRITTEN (old DATA
   freed via refcount delta).
4. If the source range falls on UNWRITTEN, no change (already zero-filled).

### 4.5 `convert_unwritten_to_data` (Commit Preallocated Write)

Range must be **exactly contained** within a single UNWRITTEN entry:

1. Find the UNWRITTEN entry containing `[off, off+len)`. If not found
   (wrong type, partial overlap), return `NotFound`.
2. Split the UNWRITTEN entry into up to three fragments:
   - `[entry_off, off)` — remaining UNWRITTEN prefix
   - `[off, off+len)` — replaced by DATA with `locator_id`, `checksum`, `birth_commit_group`
   - `[off+len, entry_end)` — remaining UNWRITTEN suffix

`alloc_bytes` is unchanged (both UNWRITTEN and DATA consume space).

### 4.6 `delete_range` (Low-level Removal)

Removes all entries overlapping `[off, off+len)`, splitting straddling entries
like `punch_hole`. Used by internal migration and space-reclaim paths.

## 5. Query Algorithms

### 5.1 `lookup_range(offset, length)`

Returns all entries intersecting `[offset, offset+length)`. The algorithm uses
binary search for the first entry whose `end_offset() > offset`, then iterates
forward while `entry.logical_offset < offset+length`.

- V1: Direct binary search on the sorted `Vec`.
- V2/V3: B+tree range scan from the leaf containing `offset`.

### 5.2 `seek_data(offset)` / `seek_hole(offset)`

POSIX `lseek(SEEK_DATA)` / `lseek(SEEK_HOLE)` semantics:

- **SEEK_DATA**: Walk entries from `offset` forward. The first entry with
  `consumes_space() == true` (i.e. UNWRITTEN or DATA) reports its
  `logical_offset`. Returns `None` if no data/unwritten entry exists past
  `offset` (including past `file_size`).

- **SEEK_HOLE**: Walk entries from `offset` forward. A hole exists:
  - Before the first entry (if `offset < first_entry.logical_offset`)
  - Between entries (if `e1.end_offset() < e2.logical_offset`)
  - Past the last entry (if `offset < file_size` and no entry covers it)

  Returns `(hole_start, hole_length)`, or `None` if the entire range past
  `offset` is covered by non-hole entries.

### 5.3 `fiemap(offset, length)`

Returns `FiemapExtent` records for `FS_IOC_FIEMAP`:

| Extent type | `fe_physical` | `fe_flags` |
|------------|--------------|-----------|
| DATA | Resolved from `locator_id` via locator table | 0 (or `FLAG_LAST` if last) |
| UNWRITTEN | 0 | `FIEMAP_EXTENT_UNWRITTEN \| FIEMAP_EXTENT_UNKNOWN` |
| HOLE | Not reported (implicit gap) | — |

The last extent in the range sets `FIEMAP_EXTENT_LAST`. Holes between reported
extents are inferred by the kernel from the gap in `fe_logical` ranges.


every mutation during test, and optionally at runtime:

| # | Invariant | Check |
|---|-----------|-------|
| 1 | `version` matches representation | `version == 1/2/3` |
| 2 | Entries sorted by `logical_offset` | Monotonic scan |
| 3 | No overlapping entries | `e[i].end_offset() <= e[i+1].logical_offset` |
| 4 | No zero-length entries | `length > 0` for every entry |
| 5 | `entry_count` matches actual count | Header vs vector/tree count |
| 6 | `alloc_bytes` matches sum of space-consuming entries | `sum(length) where consumes_space()` |
| 7 | No entry past `file_size` | `e.end_offset() <= file_size` |
| 8 | UNWRITTEN entries have zero `locator_id` and zero `checksum` | Field check |
| 9 | DATA entries have non-zero `locator_id` | `locator_id != LocatorId::NONE` |
| 10 | `file_size` >= last entry's `end_offset()` | Boundary check |

Violations return `ExtentMapError::Corrupt`, `OverlappingExtent`, `WrongVersion`,
or `MapFull` as appropriate.

## 7. Integration Points

### 7.1 With the Locator Table

For DATA entries, `locator_id` is a key into the pool-global locator table
(`crates/tidefs-locator-table/`). The locator table resolves:

- Physical location (device + grain offset + grain count)
- Refcount tracking
- Compression and encryption metadata
- Birth/death commit_group lifecycle

UNWRITTEN entries have `locator_id = LocatorId::NONE` (zero) and never touch
the locator table. This means an UNWRITTEN extent allocates space (it
contributes to `alloc_bytes`) but has no physical backing extent — the
filesystem promises zero-fill on read without allocating actual LBA space.

### 7.2 With the Inode Record

The inode carries `extent_map_version` (1/2/3) and optionally the entire
V1 inline entry array. The `file_size` and `alloc_bytes` fields in the
extent-map header are the authoritative sources for `stat(2)`:

```
st_size  = file_size
st_blocks = alloc_bytes / 512  (POSIX: 512-byte block count)
```

### 7.3 With POSIX FUSE Adapter

| POSIX operation | Calls |
|----------------|-------|
| `fallocate(mode=0)` | `insert_extent([unwritten_entry])` |
| `fallocate(FALLOC_FL_PUNCH_HOLE)` | `punch_hole(off, len)` |
| `fallocate(FALLOC_FL_ZERO_RANGE)` | `zero_range(off, len)` |
| `lseek(SEEK_DATA)` | `seek_data(off)` |
| `lseek(SEEK_HOLE)` | `seek_hole(off)` |
| `ioctl(FS_IOC_FIEMAP)` | `fiemap(off, len)` |
| `write(2)` | `insert_extent([data_entry])` or `convert_unwritten_to_data(...)` |

### 7.4 With Refcount Delta Cleanup (#1180)

When a DATA extent is freed (via `punch_hole`, `truncate` shrink, or CoW
overwrite), its `locator_id` is queued for refcount decrement in the refcount
delta queue. The queue batches decrements within a commit_group and atomically commits
them. UNWRITTEN extents have no locator-table entry to free.

## 8. Design Tradeoffs

### 8.1 HOLE as Implicit Gap vs. Explicit Entry

**Chosen**: Implicit gap.
**Alternatives considered**: Explicit hole entry.

| Approach | Pro | Con |
|----------|-----|-----|
| Implicit gap | Zero storage for holes; matches ZFS/ext4/XFS behavior | Hole queries require edge-aware traversal |
| Explicit entry | Uniform entry-based iteration for all queries | 89 bytes per hole; pollutes entry count; complicates merge logic |

The chosen approach is consistent with the industry and avoids metadata bloat.
The traversal cost is bounded by entry count (≤6 for V1, O(log n) for V2/V3),
so the performance impact is negligible.

### 8.2 V2/V3 Mutation: Collect-then-Rebuild vs. In-Place B-tree Mutation

**Chosen**: Collect-then-rebuild for V2; split-merge for V3.
**Rationale**: V2 B-tree in-place mutation with Rust's borrow checker is complex
and error-prone. The collect-then-rebuild approach is O(n) per mutation but
guarantees correctness with no unsafe code. For the V2 sweet spot (≤100K entries),
this is acceptable — the rebuild is page-local and amortized over many reads.

V3 uses multi-level structure to achieve O(log n) writes by splitting only
affected pages, but the mutation logic (insert/split/delete) is still applied
to the collected leaf-level entry list.

### 8.3 89-Byte Entry vs. Smaller Fixed Record

The 89-byte entry carries a 32-byte BLAKE3-256 checksum and 16-byte locator ID.
Alternatives like a 24-byte entry (offset+length+type+locator_index) would save
space but lose checksum locality and require additional lookups. The 89-byte
design is self-contained — a leaf page (4 KiB with 54-byte header) holds 45 entries,
which is sufficient for the vast majority of files.

### 8.4 Hysteresis in Polymorphic Switching

Promote at 6, demote at 4 (V1↔V2); promote at 100K, demote at 50K (V2↔V3).
The hysteresis gap prevents thrashing when entry counts oscillate. The gap
widths are tuned for the expected granularity of extent allocation: a single
`fallocate` or `punch_hole` rarely changes entry count by more than 2, so
the gap safely absorbs transient fluctuations.

## 9. Comparison with ZFS

| Aspect | ZFS | TideFS |
|--------|-----|--------|
| State model | 2-state (allocated/unallocated) | 3-state explicit (HOLE/UNWRITTEN/DATA) |
| UNWRITTEN signal | `DVA_ASIZE == 0` in block_ref | `extent_kind = 1` in `ExtentMapEntryV2` |
| HOLE signal | No block pointer | No extent map entry |
| `st_blocks` | `dn_phys->dn_used_bytes` from block_ref chain | `alloc_bytes` from extent header |
| SEEK_HOLE/DATA | `dmu_offset_next()` walking block_ref tree | Direct extent-list scan with binary search |
| FIEMAP | `zfs_fiemap()` traversing block_ref tree | Direct extent iteration + locator resolution |
| fallocate zero_range | Creates written extents (zero-filled) | Creates UNWRITTEN extents (allocates space, no write) |
| Recordsize | Fixed at dataset creation | Per-file via extent alignment policy |

The key TideFS advantage: separating UNWRITTEN from HOLE as explicit states
makes `SEEK_DATA/SEEK_HOLE` and `st_blocks` correct by construction rather
than by convention. ZFS's `DVA_ASIZE == 0` hack means an "allocated" block
must be checked for zero DVA size before counting it — a subtle distinction
that has produced bugs in ZFS's `lseek` implementation.

## 10. Testing Strategy


- **Unit tests** in `tidefs-extent-map`: 49 V1 tests, 23 V2 tests, 18 V3 tests,
  12 polymorphic tests — all exercising HOLE/UNWRITTEN/DATA transitions.
- **xfstests coverage**: `generic/015`, `062`, `076`, `080`, `092`, `112` for
  `st_blocks` correctness; `generic/285`, `436`, `445`, `448`, `490` for
  SEEK_HOLE/SEEK_DATA.

## 11. Implementation Status (as of 2026-05-04)

| Component | Crate | Status |
|-----------|-------|--------|
| `ExtentType` enum + predicates | `tidefs-types-extent-map-core` | Complete |
| `ExtentMapEntryV2` (89-byte record) | `tidefs-types-extent-map-core` | Complete |
| `ExtentMapOps` trait (9 methods) | `tidefs-types-extent-map-core` | Complete |
| V1 InlineExtentMap (full tristate) | `tidefs-extent-map` | Complete |
| V2 BTreeExtentMap (full tristate) | `tidefs-extent-map` | Complete |
| V3 MultiLevelBTreeExtentMap (full tristate) | `tidefs-extent-map` | Complete |
| PolymorphicExtentMap (hysteresis switching) | `tidefs-extent-map` | Complete |

### 11.1 Future Work

| Phase | Description | Depends on |
|-------|-------------|-----------|
| Inode integration | Wire `extent_map_version` into `InodeRecord` | Locator table V2 |
| FUSE adapter wiring | Connect `fallocate`/`lseek`/`fiemap` to ExtentMapOps | Inode integration |
| `FALLOC_FL_COLLAPSE_RANGE` / `INSERT_RANGE` | POSIX range-shift semantics | #1198 |
| Locator table physical resolution | Synthetic `device:offset` mapping → production | Block-map service |
| Admin tooling | `tidefsctl dataset freeze-extent-map` | Control plane API |

## 12. Non-claims (Explicit Boundaries)

- This design describes the extent map semantic layer. On-media page persistence,
  checksumming, and recovery are covered by #1285.
- Distributed extent-map replication (across cluster nodes) is deferred to the
  cluster coherency design.
- `FALLOC_FL_COLLAPSE_RANGE` and `FALLOC_FL_INSERT_RANGE` are deferred to #1198.
- Direct I/O (`O_DIRECT`) interaction with UNWRITTEN extents is deferred to the
  block-volume adapter contract.
- The FIEMAP synthetic physical offset scheme (locator to block number) uses
  `device_id * device_capacity + grain_offset` in this design; a production
  block-map service is deferred.

## 13. References

- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` — Canonical tristate semantics spec (#1225)
- `docs/design/polymorphic-extent-maps-design.md` — Polymorphic representation switching (#1555)
- `crates/tidefs-extent-map/src/lib.rs` — InlineExtentMap (V1) implementation
- `crates/tidefs-extent-map/src/btree.rs` — BTreeExtentMap (V2) implementation
- `crates/tidefs-extent-map/src/multi_level.rs` — MultiLevelBTreeExtentMap (V3) implementation
- `crates/tidefs-extent-map/src/polymorphic.rs` — PolymorphicExtentMap delegation + switching
- `crates/tidefs-types-extent-map-core/src/lib.rs` — ExtentMapOps trait, ExtentMapEntryV2, headers, constants
- `crates/tidefs-locator-table/src/lib.rs` — Locator table integration

## 14. Changelog

| Date | Change | Issue |
|------|--------|-------|
| 2026-05-04 | Auto-generated coordinator issue; design-spec maturity confirmed; Rust implementation deferred to wire-up issues | #1688 |
| 2026-05-05 | Coordinator issue #1974: design-spec closure review; cargo check --workspace passes; no code changes (design-only issue) | #1974 |
| 2026-05-05 | Coordinator issue #1816: design-spec re-verification; document covers architecture, data structures, algorithms, and tradeoffs; cargo check --workspace passes; no Rust implementation changes | #1816 |
