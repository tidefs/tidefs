# V1 Extent Map Tristate Model Design (P1 hard-gate)

**Confirmed**: [#1912](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1912) — Rust implementation confirmed; tristate model is fully implemented in `tidefs-types-extent-map-core` + `tidefs-extent-map` (InlineExtentMap, BTreeExtentMap, MultiLevelBTreeExtentMap, PolymorphicExtentMap).

**Coord**: [#2102](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2102) (coordination seal)

Maturity: **design-sealed** — design spec sealed as the single authoritative
reference for the HOLE/UNWRITTEN/DATA tristate extent model that underpins
all byte-range mutations, sparse-space accounting, `lseek(SEEK_HOLE/SEEK_DATA)`,
`FIEMAP`, `fallocate`, and `stat(2)` block count correctness. Rust implementation
of phases 5–10 deferred to wire-up issues tracked in #1877.

## Coordination Seal (#2102)

This document is the canonical design specification for the V1 extent map
tristate model. It supersedes the earlier design work that closed #1225.

The design spec is sealed as authoritative under #2102. No further design
changes are permitted. Rust implementation of phases 5–10 (inode integration,
gating) is deferred to wire-up issues as defined in the sealed design spec,
tracked under #1877.

This document closes Forgejo issue #1225.

## 1. Motivation

POSIX filesystem tests (xfstests generic/001 through generic/999) demand
correct behaviour for three distinct byte-range states within a regular file:

- **Sparse holes.** `truncate` extending beyond written data creates holes;
  `lseek(SEEK_HOLE)` must find them; `stat(2) st_blocks` must not count them.
- **Preallocated-but-unwritten regions.** `fallocate` without `FALLOC_FL_ZERO_RANGE`
  creates unwritten extents; reads return zero; `stat(2) st_blocks` must count
  them; `SEEK_DATA` must find them.
- **Data-bearing regions.** `write(2)` creates data extents; reads return stored
  bytes; `st_blocks` must count them.

Without a precise three-state model, these operations silently conflate hole,
unwritten, and data -- producing incorrect `st_blocks`, misleading `SEEK_HOLE`
results, and `FIEMAP` output that violates the kernel contract.

ZFS handles this with a two-state model (allocated/not-allocated) plus a
`BP_IS_HOLE` macro and a separate `object_node_phys::dn_maxblkid` for size. The
UNWRITTEN state is modeled as a block pointer with `DVA_ASIZE == 0`. This is
functional but conflates two distinct lifetime phases: allocated-but-zero
vs. actually-written.

TideFS makes these states explicit and principled:

- Each state has a defined answer for every query (read, SEEK, FIEMAP, stat).
- Mutation rules are a deterministic range-edit algebra.

## 2. Three Canonical States

### 2.1 HOLE

- **Representation**: implicit gap between entries in the extent map. No
  on-media entry exists. Bytes in `[0, file_size)` that are not covered
  by any `ExtentMapEntry` are HOLE.
- **Read:** returns zero bytes.
- **`st_blocks`:** not counted.
- **`SEEK_DATA`:** skips over hole, returns next DATA or UNWRITTEN offset.
- **`SEEK_HOLE`:** returns the start of the hole.
- **FIEMAP:** not reported (implicit gap between returned extents).
- **Creation:** `truncate` extend, `ftruncate` extend, `punch_hole` result,
  EOF after final extent.
- **Destruction:** `write` into hole, `zero_range` (becomes UNWRITTEN),
  `fallocate` (becomes UNWRITTEN).

### 2.2 UNWRITTEN

- **Representation**: explicit `ExtentMapEntry` with `extent_kind = UNWRITTEN`
  (1). Has `logical_offset`, `length`. Has no backing extent: `locator_id` is
  all-zero.
- **Read:** returns zero bytes without reading any physical extent.
- **`st_blocks`:** counted. `alloc_bytes` includes UNWRITTEN bytes.
- **`SEEK_DATA`:** reports the start of the UNWRITTEN extent (same as DATA:
  there are data semantics for the purpose of finding data regions).
- **`SEEK_HOLE`:** skips over UNWRITTEN (unwritten is not a hole).
- **FIEMAP:** reported with `fe_physical = 0`, `FIEMAP_EXTENT_UNWRITTEN |
  FIEMAP_EXTENT_UNKNOWN` flags.
- **Creation:** `fallocate(mode=0)` (allocate), `fallocate(FALLOC_FL_KEEP_SIZE)`,
  `zero_range` on HOLE.
- **Destruction:** `write` into unwritten (replaced by DATA, `alloc_bytes`
  unchanged), `punch_hole` (removed, `alloc_bytes` decreases), `truncate`
  shrink (entries past new EOF dropped).

### 2.3 DATA

- **Representation**: explicit `ExtentMapEntry` with `extent_kind = DATA` (0).
  Has non-zero `locator_id`, `checksum`, and `birth_commit_group`.
- **Read:** returns stored bytes from the physical extent via the locator.
- **`st_blocks`:** counted. `alloc_bytes` includes DATA bytes.
- **`SEEK_DATA`:** reports the start of the DATA extent.
- **`SEEK_HOLE`:** skips over DATA.
- **FIEMAP:** reported with resolved physical offset from `locator_id`.
  `fe_flags = 0` (or `FIEMAP_EXTENT_LAST` if last extent).
- **Creation:** `write` into HOLE, `write` into UNWRITTEN.
- **Destruction:** `punch_hole` (removed, `alloc_bytes` decreases), `truncate`
  shrink, CoW replacement on `write` into existing DATA (old DATA freed after
  refcount decrement, new DATA replaces it).

## 3. On-Media Extent Map Entry

### 3.1 ExtentMapEntry canonical record

The authoritative record for a single byte range is:

```
ExtentMapEntry {
    logical_offset: u64,     // byte offset within file, must be >= 0
    length: u64,             // bytes covered, must be > 0
    extent_kind: u8,         // 0 = DATA, 1 = UNWRITTEN
    flags: u8,               // reserved, must be 0
    locator_id: [u8; 16],    // zero for UNWRITTEN; locator table key for DATA
    checksum: [u8; 32],      // BLAKE3-256 over logical byte range; zero for UNWRITTEN
    birth_commit_group: u64,          // commit_group that created this entry
    reserved: [u8; 15],      // fixed to zero; TLV extension anchor
}
// Total: 8 + 8 + 1 + 1 + 16 + 32 + 8 + 15 = 89 bytes
```

**HOLE is implicit.** There is no HOLE entry. Gaps between entries are holes.
Bytes from the last entry's `logical_offset + length` up to `file_size` are
holes.

**Locator id for DATA.** For DATA extents, `locator_id` points into the pool-
global `ExtentLocatorTable` (see #1285). The locator table resolves
`locator_id` to `(device_id, physical_offset, physical_length, checksum,
refcount, ...)`.

**Locator id for UNWRITTEN.** For UNWRITTEN extents, `locator_id` is the
all-zero `[u8; 16]`. This distinguishes UNWRITTEN from DATA without a separate
boolean check: `locator_id == [0u8; 16]` iff UNWRITTEN.

**Birth commit_group.** Every extent carries the commit_group number that created it. This is
used for:
- Snapshot hold: extents with `birth_commit_group > oldest_live_snapshot_commit_group` are
  protected.
- Crash recovery: after replay, extents with `birth_commit_group > last_committed_commit_group`
  are discarded.
- Deadlist entry: when an extent is freed, `death_commit_group` is recorded at the
  locator table level, not in the extent map entry.

### 3.2 Adjacency and coalescing

Adjacent entries of the same kind are **not coalesced** unless their physical
mapping is also contiguous. This preserves the following property: every
`ExtentMapEntry` maps to exactly one `ExtentLocatorValue`, making refcount
operations O(1) per entry.

```
Example (not coalesced):
  [0, 4096, DATA, loc_A] [4096, 4096, DATA, loc_B]
  // Two distinct locator ids, two extent map entries.

Example (coalescable):
  [0, 4096, DATA, loc_A] [4096, 4096, DATA, loc_A_next_contiguous]
  // Same locator id family, contiguous on disk -- may coalesce to:
  [0, 8192, DATA, loc_A]
```

method does not require maximal coalescing.

## 4. Canonical Invariants

After every mutation (write, fallocate, punch_hole, truncate, zero_range),
called before every commit and may panic or return an error on violation.

### Invariant Checklist

| # | Invariant | Enforcement |
|---|---|---|
| I1 | Entries sorted by `logical_offset` ascending | Assert `e[i].logical_offset < e[i+1].logical_offset` |
| I2 | No overlap: `e[i].logical_offset + e[i].length <= e[i+1].logical_offset` | Runtime check after every insertion |
| I3 | No zero-length entries: `length > 0` | Reject on insert |
| I4 | No entries beyond `file_size`: last entry's `logical_offset + length <= file_size` | Trim on truncate, reject on write |
| I5 | `alloc_bytes = sum(length) for all entries where extent_kind in (DATA, UNWRITTEN)` | Recompute on demand; cached |
| I6 | `st_blocks = ceil(alloc_bytes / 512)` | Derived from I5 |
| I8 | DATA entries have non-zero `locator_id` and non-zero `checksum` | Assert on insert |
| I9 | `logical_offset` and `length` for DATA entries are recordsize-aligned (configurable, default 4 KiB) | Enforce on write path |
| I10 | `file_size` never decreases below 0 | Enforce on truncate |

### 4.1 State coverage lemma

For every byte offset `b` in `[0, file_size)`:
- If `b` is covered by a DATA entry, the byte is in DATA state.
- If `b` is covered by an UNWRITTEN entry, the byte is in UNWRITTEN state.
- Otherwise, `b` is in HOLE state.

This is exhaustive and mutually exclusive: no byte can be in two states
simultaneously. The invariant trivially holds because entries are non-
overlapping (I2), and HOLE is the implicit state for non-covered bytes.

## 5. Mutation Rules (Range-Edit Algebra)

All mutations operate on a byte range `[offset, offset + length)`. Each
mutation is defined by how it transforms the states of the bytes within
the range, plus how it updates `file_size` and `alloc_bytes`.

### 5.1 write(offset, data)

Overwrites a range with DATA. The target range is converted to DATA regardless
of prior state:

```
write(offset, data):
  length = data.len()
  for each byte in [offset, offset + length):
    prior = state(byte)
    write DATA to byte
    if prior == HOLE:       alloc_bytes += 1
    if prior == UNWRITTEN:  alloc_bytes unchanged
    if prior == DATA:       alloc_bytes unchanged; old extent refcount decremented;
                            new extent created (CoW)
  file_size = max(file_size, offset + length)
```

**CoW semantics for DATA overwrite.** When writing into existing DATA, the
old extent's `locator_id` refcount is decremented via the refcount delta
queue (#1180). The new DATA extent gets a fresh `locator_id` with a new
physical allocation. This preserves snapshot isolation: the old extent
remains live if any snapshot holds it.

### 5.2 fallocate(offset, length, mode=0)

Preallocates space without writing data. Creates UNWRITTEN extents:

```
fallocate(offset, length, mode=0):
  for each byte in [offset, offset + length):
    prior = state(byte)
    if prior == HOLE:
      create UNWRITTEN extent
      alloc_bytes += 1
    if prior == UNWRITTEN:
      no change
    if prior == DATA:
      no change  // fallocate does not convert DATA to UNWRITTEN
  file_size = max(file_size, offset + length)
```

`mode=0` extends the file if `offset + length > file_size`. With
`FALLOC_FL_KEEP_SIZE`, `file_size` is not extended; bytes beyond
`file_size` are not affected.

### 5.3 punch_hole(offset, length)

Deallocates a range, converting it to HOLE:

```
punch_hole(offset, length):
  for each byte in [offset, offset + length):
    prior = state(byte)
    if prior == HOLE:
      no change
    if prior == UNWRITTEN:
      remove UNWRITTEN extent
      alloc_bytes -= 1
    if prior == DATA:
      decrement locator refcount via refcount queue
      remove DATA extent
      alloc_bytes -= 1
  // Do not change file_size when FALLOC_FL_KEEP_SIZE is implied
```

After punch_hole, the range is HOLE. Adjacent extents on either side remain
unchanged. The gap between them is now a hole.

### 5.4 zero_range(offset, length)

Converts a range to UNWRITTEN (allocated, reads as zero):

```
zero_range(offset, length):
  for each byte in [offset, offset + length):
    prior = state(byte)
    if prior == HOLE:
      create UNWRITTEN extent
      alloc_bytes += 1
    if prior == UNWRITTEN:
      no change
    if prior == DATA:
      decrement locator refcount via refcount queue
      create UNWRITTEN extent
      // alloc_bytes unchanged: DATA -> UNWRITTEN is same size
  file_size = max(file_size, offset + length)
```

### 5.5 truncate(new_size)

Changes `file_size`. Extents beyond `new_size` are removed:

```
truncate(new_size):
  if new_size > file_size:
    // Extend: bytes [file_size, new_size) become HOLE
    file_size = new_size
    // alloc_bytes unchanged

  if new_size < file_size:
    // Shrink: drop entries or entry portions past new_size
    for each extent e with e.logical_offset >= new_size:
      if e.kind in (DATA, UNWRITTEN):
        alloc_bytes -= e.length
      remove e
    if an extent e spans new_size:
      truncate e.length to new_size - e.logical_offset
      alloc_bytes -= (old_length - new_length)
    file_size = new_size

```

### 5.6 write_range(offset, data)

Same as `write` but operates on a sub-range without extending `file_size`
(unless `offset + data.len() > file_size`):

```
write_range(offset, data):
  // Only affects bytes within [offset, min(offset + len, file_size)]
  // Extends file_size if writing past EOF
  effective_end = max(offset + data.len(), file_size)
  // Apply write semantics to [offset, effective_end)
  write(offset, data[0..effective_end - offset])
```

## 6. SEEK_HOLE and SEEK_DATA Semantics

The kernel's `lseek(SEEK_HOLE)` and `lseek(SEEK_DATA)` are defined in terms
of the tristate model:

### 6.1 State classification for SEEK

| State | `SEEK_DATA` | `SEEK_HOLE` |
|---|---|---|
| HOLE | Skips | Returns |
| UNWRITTEN | Returns | Skips |
| DATA | Returns | Skips |
| Beyond EOF | Returns `ENXIO` | Returns `file_size` |

### 6.2 Algorithm: seek_data(offset)

```
seek_data(offset):
  if offset >= file_size:
    return ENXIO

  for each extent e with e.logical_offset >= offset:
    if e.kind in (DATA, UNWRITTEN):
      return e.logical_offset  // first data or unwritten extent at or after offset

  // No data extents found past offset: past EOF
  return ENXIO
```

### 6.3 Algorithm: seek_hole(offset)

```
seek_hole(offset):
  if offset >= file_size:
    return file_size  // EOF is always a hole boundary

  for each byte b from offset to file_size:
    if state(b) == HOLE:
      return b  // first hole byte

  // Entire file from offset is DATA or UNWRITTEN
  return file_size  // hole at EOF
```

### 6.4 xfstests coverage

The following xfstests exercise SEEK_HOLE/SEEK_DATA and depend on correct
tristate semantics:

```
generic/285  SEEK_HOLE/SEEK_DATA in unwritten extents
generic/286  SEEK_HOLE/SEEK_DATA in sparse files
generic/436  SEEK_HOLE/SEEK_DATA with fallocate and punch_hole
generic/437  SEEK_HOLE/SEEK_DATA after write into unwritten extent
generic/448  SEEK_DATA past EOF -> ENXIO
generic/490  SEEK_HOLE/SEEK_DATA with direct I/O
generic/530  SEEK_HOLE/SEEK_DATA on files with only unwritten extents
generic/531  SEEK_HOLE/SEEK_DATA after ftruncate extend
```

## 7. FIEMAP Semantics

`FS_IOC_FIEMAP` returns extent-level mapping information. The tristate
model determines what is reported:

### 7.1 Per-extent FIEMAP output

| Extent kind | `fe_physical` | `fe_flags` | `fe_length` |
|---|---|---|---|
| DATA | Resolved from locator: `(device_id, physical_offset)` mapped to synthetic block number | `0` (or `FIEMAP_EXTENT_LAST` if last) | `length` |
| UNWRITTEN | `0` | `FIEMAP_EXTENT_UNWRITTEN \| FIEMAP_EXTENT_UNKNOWN` | `length` |
| HOLE | Not reported | -- | -- |

### 7.2 FIEMAP algorithm

```
fiemap(start, length, max_extents):
  result = []
  for each extent e intersecting [start, start + length):
    if e.kind == HOLE:
      continue  // holes are implicit in FIEMAP
    entry = FiemapExtent {
      fe_logical: e.logical_offset,
      fe_length: min(e.length, start + length - e.logical_offset),
      fe_physical: if e.kind == DATA { resolve_physical(e.locator_id) } else { 0 },
      fe_flags: if e.kind == UNWRITTEN {
          FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_UNKNOWN
        } else if last_extent {
          FIEMAP_EXTENT_LAST
        } else { 0 },
    }
    result.push(entry)
    if result.len() >= max_extents:
      break
  return result
```

### 7.3 FIEMAP_FLAG_SYNC

When `FIEMAP_FLAG_SYNC` is set in the ioctl, the implementation triggers
a commit_group sync before querying the extent map, ensuring all dirty data
and metadata are committed and reflected in the map.

## 8. stat(2) Block Count Semantics

### 8.1 Derivation

```
alloc_bytes = sum(extent.length for all extents where extent_kind in (DATA, UNWRITTEN))
st_blocks = (alloc_bytes + 511) / 512   // POSIX: 512-byte block units
```


After every mutation, `st_blocks` must reflect only DATA and UNWRITTEN bytes:

```
assert(st_blocks == (alloc_bytes + 511) / 512)
assert(alloc_bytes == sum(length of non-HOLE entries))
assert(alloc_bytes <= file_size)  // HOLE bytes not counted
```

### 8.3 xfstests coverage


```
generic/015  st_blocks after fallocate
generic/062  st_blocks after punch_hole
generic/076  st_blocks on sparse files
generic/080  st_blocks after write/truncate
generic/092  st_blocks after hole punching and re-writing
generic/112  st_blocks after fallocate + write
```

## 9. Integration Points

### 9.1 With ExtentMap B-tree (#1285)

The tristate model is the semantic layer; the extent map B-tree is the
storage layer. Every `ExtentMapEntry` in the B-tree carries `extent_kind`.
The B-tree itself treats all entries uniformly for search/insert/delete;
the tristate semantics are enforced at the `ExtentMap` level above the
B-tree.

### 9.2 With ExtentLocatorTable (#1285)

For DATA entries, `locator_id` is the key into the pool-global locator
table. The locator table handles:
- Physical location resolution (device + offset)
- Refcount tracking
- Compression/encryption metadata
- Birth/death commit_group lifecycle

UNWRITTEN entries have zero `locator_id` and never touch the locator table.

### 9.3 With Refcount Delta Cleanup Queues (#1180)

When a DATA extent is freed (via punch_hole, truncate shrink, or CoW
overwrite), its `locator_id` refcount is decremented through the refcount
delta queue. The queue batches decrements within a commit_group and atomically commits
them with the extent refcount B-tree.

### 9.4 With POSIX FUSE Adapter

The FUSE adapter's `fallocate`, `lseek`, and `ioctl(FS_IOC_FIEMAP)` handlers
call into the extent map tristate methods:

```
fallocate  -> ExtentMap::fallocate()
lseek       -> ExtentMap::seek_data() / ExtentMap::seek_hole()
fiemap      -> ExtentMap::fiemap()
stat        -> InodeRecord::st_blocks (derived from alloc_bytes)
```

### 9.5 With Polymorphic Extent Maps (#1291)

When the extent map representation switches from V1 (inline) to V2 (B-tree)
or to multi-level B-tree, the tristate semantics are preserved. The switching
layer deals only with representation; the mutation rules in section 5 are
representation-agnostic.

## 10. Comparison with ZFS

| Aspect | ZFS | TideFS |
|---|---|---|
| State model | 2-state (allocated via block_ref, not-allocated) | 3-state explicit (HOLE/UNWRITTEN/DATA) |
| UNWRITTEN representation | Block pointer with `DVA_ASIZE == 0` | `ExtentMapEntry` with `extent_kind = UNWRITTEN`, locator_id = 0 |
| HOLE representation | No block pointer (implicit) | No extent map entry (implicit) |
| `st_blocks` derivation | `dn_phys->dn_used_bytes` from block pointer chain | `alloc_bytes = sum(length of non-HOLE entries)` |
| SEEK_HOLE/DATA | dmulib `dmu_offset_next()` walking block_ref tree | Direct extent map scan (O(#extents)) |
| FIEMAP | `zfs_fiemap()` traversing block_ref tree | Direct extent map iteration with locator resolution |
| fallocate zero_range | Creates written extents with zero-fill | Creates UNWRITTEN extents (allocates space without writing) |
| Recordsize | Fixed at dataset creation | Configurable per file via extent alignment policy |



```
tidefs-xtask check-extent-tristate
```

This gate verifies:

1. This document exists and contains the required sections.
2. The `ExtentMapEntry` record family with `extent_kind` field is declared
   in the authoritative data structures catalog.
3. All 10 canonical invariants from section 4 are documented and reference
   their enforcement mechanism.
4. All 6 mutation rules from section 5 are specified with per-state
   transitions and `alloc_bytes`/`file_size` updates.
5. SEEK_HOLE/SEEK_DATA algorithms match the canonical POSIX definitions
   and xfstests coverage is documented.
6. FIEMAP output is specified for each extent kind.
7. `st_blocks` derivation from `alloc_bytes` is documented.
8. The ZFS comparison table demonstrates parity or improvement.

## 12. Non-claims (explicit boundaries)

- This is a design spec; the Rust implementation of the tristate model
  within `ExtentMap` methods (`fallocate`, `punch_hole`, `zero_range`,
  successor implementation issue.
- The extent map B-tree persistence layer is deferred to #1285 (Extent Maps
  and Locator Tables Design) and its implementation.
- The polymorphic representation switching (inline -> B-tree -> multi-level)
  is deferred to #1291.
- Coalescing heuristics for adjacent extent entries are optimization, not
  correctness; specific coalescing policies are deferred.
- `FALLOC_FL_COLLAPSE_RANGE` and `FALLOC_FL_INSERT_RANGE` are deferred
  to issue #1198 (POSIX semantics library).
- Direct I/O (`O_DIRECT`) interaction with unwritten extents is deferred
  to the block-volume adapter contract.
- The `FIEMAP` synthetic physical offset mapping (locator to block number)
  uses a simple `device_id * device_capacity + physical_offset` scheme in
  the design; a production block-map service is deferred.
