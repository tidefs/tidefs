# Extent Maps and Locator Tables Design (P1 hard-gate)

Maturity: **design-spec** for the extent map and locator table data structures
that form the byte-range-to-physical-mapping core of TideFS.

This document closes Forgejo issue #1285.

## 1. Motivation

The current chunk-manifest model (`ContentManifestObject` with a flat
`Vec<ContentChunkRef>`) has two structural limits:

- **No variable-size extents.** Every chunk is exactly
  `FILESYSTEM_CONTENT_CHUNK_SIZE`. A 1 TiB file with a single dirty byte at
  offset 0 still carries a full manifest of 262,144 chunk references, and
  random writes at large offsets pay O(n) scan cost to locate the target chunk.
- **No physical indirection.** Chunk identity is directly embedded in the
  manifest. Relocating data (e.g., segment retirement, tiering, or rebalance)
  requires rewriting every manifest that references the moved chunks, which is
  an O(files x chunks) catastrophe.

This design introduces two decoupled structures:

- **Extent Map** -- per-file B-tree mapping `(logical_offset, extent_id)` to
  variable-length byte ranges with HOLE/UNWRITTEN/DATA tristate semantics.
- **Locator Table** -- pool-global B-tree that translates `locator_id` into
  physical device + offset, enabling online relocation without touching any
  extent map.

## 2. Relationship to Existing Types

| Current type | Replaced by | Migration path |
|---|---|---|
| `ContentManifestObject` (flat `Vec<ContentChunkRef>`) | `ExtentMapV2` (B-tree) | Read old manifests as compatibility input; rewrite on next mutation |
| `ContentChunkRef` (chunk_index, data_version, len, checksum) | `ExtentMapEntryV2` + `ExtentLocatorValueV1` | Per-entry fields distributed across extent maps and locator table |
| `ContentChunkObject` (per-chunk store object) | `ShardPayload` (issue #1286) | Content chunks become shard payloads under the locator layer |

## 3. Tristate Extent Model

Per #1225, every logical byte range in a regular file is in exactly one of
three states:

| State | On-media entry | `st_blocks` | `SEEK_DATA` | `SEEK_HOLE` | Created by |
|---|---|---|---|---|---|
| HOLE | None (implicit gap) | Not counted | No | Yes | Truncate-extend, never-written |
| UNWRITTEN | Explicit `ExtentMapEntryV2` with `kind=UNWRITTEN` | Counted | Yes | No | `fallocate` |
| DATA | Explicit `ExtentMapEntryV2` with `kind=DATA`, `locator_id` set | Counted | Yes | No | `write`, `pwrite` |

### 3.1 Invariant: Non-overlapping, sorted, contiguous coverage

After every mutation, the extent map must satisfy:

1. Entries are sorted by `logical_offset` ascending.
2. No two entries overlap: for any adjacent pair `e[i]`, `e[i+1]`,
   `e[i].logical_offset + e[i].length <= e[i+1].logical_offset`.
3. There is exactly one entry kind for every byte in `[0, file_size)`:
   gaps between entries are HOLE; bytes past the last entry up to
   `file_size` are HOLE.
4. `alloc_bytes = sum(length of all UNWRITTEN + DATA entries)`.
5. `st_blocks = ceil(alloc_bytes / 512)`.

after every mutation and before every commit.

## 4. Extent Map Data Structures

### 4.1 ExtentMapEntryV2 (on-media authoritative record)

```
ExtentMapEntryV2 {
    logical_offset: u64,     // byte offset within file
    length: u64,             // bytes covered (>= 4096, power-of-2 aligned when recordsize policy demands)
    extent_kind: u8,         // 0 = DATA, 1 = UNWRITTEN
    flags: u8,               // bit 0: dedup_eligible, bits 1-2: compression_hint, bits 3-7: reserved
    locator_id: [u8; 16],    // zero for UNWRITTEN; points into ExtentLocatorTable for DATA
    checksum: [u8; 32],      // BLAKE3-256 over the logical byte range; zero for UNWRITTEN
    birth_commit_group: u64,          // commit_group that created this entry
    reserved: [u8; 15],      // fixed to zero; TLV extension anchor
}
// Total: 8 + 8 + 1 + 1 + 16 + 32 + 8 + 15 = 89 bytes
```

### 4.2 ExtentMap (per-file B-tree root)

The extent map is stored as a B-tree with the following properties:

```
ExtentMap {
    root_page_locator: LocatorId,  // root B-tree page, in the locator table
    entry_count: u64,
    alloc_bytes: u64,              // sum(length of non-HOLE entries)
    file_size: u64,
    depth: u8,                     // B-tree depth (0 = single leaf)
    flags: u8,                     // bit 0: large_file (use V2 pages), bits 1-7: reserved
    reserved: [u8; 6],
}
// Total: 16 + 8 + 8 + 8 + 1 + 1 + 6 = 48 bytes
```

The B-tree key is `(logical_offset, extent_id)`. The `extent_id` is derived
from `sha256(logical_offset || locator_id)[0..16]` to provide a stable,
content-addressed identity that survives relocation.

### 4.3 B-tree page layout

```
ExtentMapPageHeader {
    magic: [u8; 4],             // "EXMP"
    page_kind: u8,              // 0 = leaf, 1 = internal
    entry_count: u16,
    level: u8,                  // 0 = leaf, 1+ = internal
    checksum: [u8; 32],         // BLAKE3-256 over page content
    reserved: [u8; 14],
}
// Total: 4 + 1 + 2 + 1 + 32 + 14 = 54 bytes

ExtentMapLeafPage {
    header: ExtentMapPageHeader,
    entries: [ExtentMapEntryV2; entry_count],  // variable; up to page_size
}

ExtentMapInternalPage {
    header: ExtentMapPageHeader,
    // Sorted array of (separator_key, child_page_locator) pairs
    separators: [(u64, LocatorId); entry_count],
}
```

The default page size is 4096 bytes, configurable via the pool property
`extent_map_page_size`. A 4 KiB leaf page holds approximately 45 entries
(4096 - 54) / 89, covering ~180 KiB of file data at 4 KiB extent granularity.
A 4-level tree (depth 3) can address ~1.6 PiB.

### 4.4 V1 vs V2 distinction

- **ExtentMapV1** (small files, depth 0, page_size == extent): Inline in the
  `InodeRecord`, no separate B-tree pages. Limited to ~6 entries (~24 KiB at
  4 KiB extents).
- **ExtentMapV2** (large files or files with UNWRITTEN extents): Full B-tree
  with pages stored in the locator table.

The transition from V1 to V2 happens automatically when:
- Entry count exceeds `extent_map_v1_max_entries` (default: 6), or
- Any extent is UNWRITTEN, or
- The file has holes (gaps between entries).

This matches the polymorphic design principle: micro-list for small,
B-tree for large.

## 5. Locator Table Data Structures

### 5.1 ExtentLocatorValueV1 (on-media authoritative record)

```
ExtentLocatorValueV1 {
    locator_id: [u8; 16],        // primary key (content-addressed)
    device_id: u64,              // pool device id
    physical_offset: u64,        // byte offset on device
    physical_length: u64,        // bytes on disk (may differ from logical due to compression)
    logical_length: u64,         // uncompressed byte length
    checksum: [u8; 32],          // BLAKE3-256 over stored bytes
    compression: u8,             // 0 = none, 1 = zstd, 2-255 = reserved
    encryption_epoch: u64,       // wrap key epoch for encrypted extents; 0 = plaintext
    flags: u16,                  // bit 0: sharded, bit 1: erasure_coded, bits 2-15: reserved
    refcount: u32,               // number of live extent-map references
    birth_commit_group: u64,              // commit_group that created this locator
    death_commit_group: u64,              // commit_group that freed this locator; 0 = alive
    reserved: [u8; 11],          // TLV extension anchor
}
// Total: 16 + 8 + 8 + 8 + 8 + 32 + 1 + 8 + 2 + 4 + 8 + 8 + 11 = 122 bytes
```

### 5.2 ExtentLocatorTable (pool-global B-tree)

```
ExtentLocatorTable {
    root_page_locator: LocatorId,  // root B-tree page
    entry_count: u64,
    depth: u8,
    flags: u8,
    reserved: [u8; 6],
}
// Total: 16 + 8 + 1 + 1 + 6 = 32 bytes
```

The locator table B-tree is keyed by `locator_id`. It is pool-global -- all
datasets in a pool share one locator table. This is the central indirection
point that makes online relocation possible: rewrite the locator entry, and
every extent map that references it is transparently updated.

### 5.3 Locator id derivation

`locator_id` is derived from the content, not the location:

```
locator_id = blake3(
    device_id || physical_offset || physical_length || checksum ||
    birth_commit_group || content_digest
)[0..16]
```

This gives stable identity even when the physical location changes during
relocation. Two identical content payloads at different locations produce
different `locator_id` values because `device_id || physical_offset` differs.

### 5.4 Refcount tracking

The `refcount` field in `ExtentLocatorValueV1` tracks the number of extent map
entries referencing this locator. The lifecycle is:

1. **birth_commit_group**: set to the commit_group that allocates the storage.
2. **refcount increment**: on every CoW clone, snapshot hold, or reflink that
   creates a new extent map entry pointing to this locator.
3. **refcount decrement**: on every extent map entry deletion (truncate,
   punch-hole, snapshot release, overwrite).
4. **death_commit_group**: set when refcount reaches 0. The space is not immediately
   freed; it enters the deadlist for async reclamation.
5. **freed**: after the deadlist's retention policy expires (typically 2 commit_group
   epochs), the space is returned to the allocator.

This matches the ZFS birth_commit_group/death_commit_group model but adds explicit refcount
tracking visible in the locator rather than inferred from block-pointer
scanning.

## 6. Extent Lifecycle State Machine

```
                  +----------+
                  |  INGEST  |  (written by current commit_group)
                  +----+-----+
                       | commit_group commit
                  +----v-----+
                  |   BASE   |  (committed, stable)
                  +----+-----+
                       | overwrite, truncate, punch-hole, snapshot release
                  +----v-----+
                  |   DEAD   |  (refcount = 0, waiting for deadlist expiry)
                  +----+-----+
                       | deadlist expiry (2 commit_group epochs)
                  +----v-----+
                  |  FREED   |  (returned to allocator)
                  +----------+
```

The lifecycle applies to both extent map entries and locator table entries:

- **INGEST**: The extent was written in the current open commit_group. It is visible to
  the writing transaction but not yet committed. Crash before commit discards
  it.
- **BASE**: The extent has been committed and is referenced by a committed
  root. It is immutable and protected by the root-retention planner.
- **DEAD**: All references have been dropped (refcount = 0). The extent is
  snapshots that were taken before the death commit_group can still access the data.
- **FREED**: The space has been returned to the allocator and may be reused.

## 7. CoW and Snapshot Interaction

### 7.1 Copy-on-Write write path

When a DATA extent is overwritten:

1. The new data is written to a new physical location, producing a new
   `locator_id`.
2. The old extent map entry is replaced with a new `ExtentMapEntryV2`
   pointing to the new `locator_id`.
3. The old `ExtentLocatorValueV1` has its `refcount` decremented.
4. If the old locator is still referenced by a snapshot, `refcount > 0` and it
   stays alive. Otherwise, it transitions to DEAD.

### 7.2 Snapshot hold

When a snapshot is taken:

1. Every locator referenced by the snapshot's committed root has its `refcount`
   incremented atomically at the start of the snapshot commit_group.
2. Subsequent overwrites decrement the snapshot-held locators, but they stay
   alive because `refcount >= 1`.
3. When the snapshot is destroyed, a batch decrement is issued for all
   snapshot-unique locators (those whose refcount reaches 0 after the
   decrement).

### 7.3 Reflink / clone

A reflink (cross-file or cross-dataset extent sharing) creates a new extent map
entry pointing to the same `locator_id` and increments `refcount`. This is a
metadata-only operation: no data copy. The shared locator stays alive until
both files drop their references.

## 8. Algorithm Families

### 8.1 ExtentMap::lookup_range(file_offset, length) -> Vec<ExtentFragment>

Returns all extent map entries intersecting `[file_offset, file_offset + length)`.
Each returned fragment describes the extent kind (HOLE/UNWRITTEN/DATA) and,
for DATA extents, the `locator_id` and sub-range within the extent.

Algorithm: B-tree range scan on `logical_offset`. O(log n + k) where k is the
number of entries in the range.

### 8.2 ExtentMap::insert_extents(entries: Vec<ExtentMapEntryV2>)

Inserts a set of new entries into the extent map. The caller must:

1. Resolve overlaps: any existing entries fully or partially covered by the
   new entries are split, truncated, or removed.
2. Trim beyond EOF: entries past `file_size` are rejected.
3. Coalesce: adjacent entries of the same kind *and* same `locator_id` are
   merged into a single entry.

Algorithm: B-tree merge-insert with page splitting. O((log n + k) x page_depth).

### 8.3 ExtentMap::truncate(new_size: u64)

Drops all entries at or past `new_size`. If `new_size` falls within an entry,
that entry is split and the tail portion is dropped. `file_size` is updated.

Algorithm: Find the entry containing `new_size`, split it, delete everything
after. O(log n + k).

### 8.4 ExtentMap::punch_hole(offset, length)

Replaces all entries in `[offset, offset + length)` with HOLE. Equivalent to
deleting the affected entries. Affected locators have their refcounts
decremented.

Algorithm: `lookup_range` + batch delete. O((log n + k) x page_depth).

### 8.5 ExtentLocatorTable::resolve(locator_id) -> ExtentLocatorValueV1

Returns the physical location for a given locator. This is the hot path for
every read.

Algorithm: B-tree point lookup. O(log n x depth).

### 8.6 ExtentLocatorTable::relocate(old: LocatorId, new: LocatorId, new_value: ExtentLocatorValueV1)

Atomically replaces a locator entry. Used during segment retirement, tier
migration, and rebalance. The caller is responsible for ensuring the new
physical location contains valid data before the swap.

Algorithm: B-tree replace. O(log n).

### 8.7 ExtentLocatorTable::batch_decrement_refcounts(locator_ids: &[LocatorId])

Decrements refcounts for a batch of locators. Any locator that reaches
`refcount == 0` is added to the deadlist. Returns the set of newly-dead
locators for async reclamation.

Algorithm: Batch B-tree lookup + update. O(k x log n).

## 9. Integration Points

### 9.1 With InodeRecord

The `InodeRecord` gains a new field:

```
extent_map: ExtentMap,  // replaces implicit content_object_key indirection
```

For V1 (small files), the extent map is embedded inline in the inode record.
For V2, the `root_page_locator` refers to the B-tree root in the locator table.

### 9.2 With Commit/COMMIT_GROUP (#1267)

The commit_group state machine must:

1. During QUIESCE: freeze the extent map B-tree. New writes go to a new tree.
2. During SYNC step 3: flush extent map B-tree pages to the locator table.
3. During SYNC step 4: write the commit record with the root locator of the
   new extent map.
4. During SYNC step 6: update the inode's `extent_map.root_page_locator`.

### 9.3 With Allocator (#1148)

Extent allocation requests originate from the extent map layer. The allocator
returns `(device_id, physical_offset, physical_length)`. The locator table
entry is then created with these values.

### 9.4 With Shards (#1286)

For files larger than `shard_threshold_bytes`, a single logical extent may be
split across multiple shards. The `ExtentLocatorValueV1.flags` bit 0
(`sharded`) indicates this. A shard manifest (designed in #1286) maps the
logical sub-range within the extent to individual shard payloads.

## 10. On-Disk Format Rules

Per #1220 (single-V1 strategy with TLV extensions):

1. All extent map and locator table pages use the `BinaryEnvelopeHeaderRecord`
   framing with `family_id = extent_map_v1` or `locator_table_v1`.
3. TLV extension areas follow the fixed fields. Unknown TLVs are skipped.
4. Feature flags at the dataset level gate new TLV interpretation.
5. Checksums are BLAKE3-256 over the entire page content including header,
   via the production-integrity trailer format (record version 3).

## 11. Migration from ChunkedContentLayout

Existing files using `ContentLayout::Chunked(ContentManifestObject)` must be
migrated to the extent map model on first mutation:

1. Read the chunk manifest.
2. Convert each contiguous run of `ContentChunkRef`s into `ExtentMapEntryV2`:
   - HOLE sentinel chunks -> implicit gaps (no entry).
   - Data chunks -> DATA entries with newly allocated `locator_id`.
3. Write the new extent map.
4. Mark the inode as `extent_map_version = 2`.
5. Tombstone the old content manifest object.

Read-only access to files with old content manifests remains supported
indefinitely. The old manifest is treated as a compatibility input, and the
extent map is lazily constructed in memory during reads.

## 12. Performance Properties

| Operation | Current (flat Vec) | With B-tree ExtentMap |
|---|---|---|
| Read 4 KiB at offset 1 TiB | O(n) scan ~262k entries | O(log n) ~3-4 page reads |
| Append 4 KiB | O(1) push | O(log n) page insert |
| Random write 4 KiB at offset | O(n) scan + O(1) replace | O(log n) lookup + insert |
| Truncate from 1 TiB to 0 | O(n) scan + O(n) drop | O(k) where k = entries at tail |
| Punch hole 1 GiB | O(n) scan + O(n) remove | O(k) range delete |
| Relocate 1000 extents | O(files x locators) rewrite all manifests | O(locators) rewrite locator table only |



```
tidefs-xtask check-extent-maps-locator-tables
```

This gate will verify:
1. This document exists and contains the required sections.
2. The `ExtentMapEntryV2` and `ExtentLocatorValueV1` record families are
   declared in the authoritative data structures catalog.
3. The tristate HOLE/UNWRITTEN/DATA invariants are documented.
4. The B-tree page layout is specified.
5. The lifecycle state machine is documented.
6. The migration path from `ContentLayout::Chunked` is specified.

## 14. Non-claims (explicit boundaries)

- Actual Rust implementation of the B-tree is deferred to an implementation
  issue following this design.
- Shard integration (#1286) is specified at the interface level only.
- Erasure-coded extent placement is deferred to #1286.
- Dedup index integration is deferred to #1255.
- Adaptive recordsize (#1257) interacts with this design but is specified
  separately.
- The `refcount` field is specified but the deadlist algorithm for async
  reclamation is deferred to #1232.
- Compression and encryption field layout is specified but the actual
  compress-then-encrypt pipeline is deferred to #1286 and existing
  tidefs-compression / tidefs-encryption crates.
