# Compression Design Strategy: Format Extension Model, Per-Dataset Policy, and Extent Payload Integration

Maturity: **design-spec** for the compression architecture that governs how
extent payloads are compressed, the per-dataset policy contract, cache
representation, space accounting double-book, and integration with dataset
feature flags and the unified property framework.

This document closes Forgejo issue #1245.

## 1. Motivation

Storage systems compress for two reasons: reduce write amplification (fewer
bytes to disk → higher effective throughput) and improve space efficiency
(more logical data per physical terabyte). Compression must be introduced
without breaking existing on-media payloads or forcing every reader to
understand every compression algorithm.

This design defines how compression extends the V1 on-media format through
new record types gated by feature flags, how compression policy is expressed
as per-dataset properties that inherit and can be overridden, how each
extent payload carries its own compression metadata so per-extent override
is possible, and how the cache and space accounting layers surface the
logical-vs-physical double-book that compression creates.

The existing `tidefs-compression` and `tidefs-frame` crates provide a
transparent per-object compression wrapper at the object-store level. This
design extends that mechanism upward into the extent payload layer with
block-aligned semantics, and downward into the pool and dataset property
systems with feature-gated, inheritable policy.

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1220 (on-media format strategy) | New record types | Adds `EXTENT_DATA_COMPRESSED_V1` to the canonical V1 record family catalog; compression metadata travels in the record header |
| #1223 (dataset feature flags) | Feature gating | `org.tidefs:compression_lz4` and `org.tidefs:compression_zstd` as named feature flags with compat/ro_compat/incompat classification |
| #1225 (extent map tristate) | Mutation rules | Compression applies only to DATA extents; UNWRITTEN and HOLE are never compressed |
| #1285 (extent maps & locator tables) | Locator metadata | `ExtentLocatorValueV1.compression` field carries per-extent algorithm byte; `physical_length` and `logical_length` expose the compression ratio |
| #1253 (unified property framework) | Per-dataset properties | `compression`, `compression_level`, `compression_min_bytes` as registered properties with PARENT inheritance and ALWAYS change policy |
| #1215 (space accounting) | Logical vs physical | `logical_used_bytes` counts uncompressed bytes; `physical_used_bytes` (new counter) counts on-disk compressed bytes |
| #1192 (weighted ARC cache) | Admission weighting | Cache entries carry compression-ratio weight; admission policy favors retaining high-ratio (well-compressed) entries |
| #1218/#1226 (object cache) | Cache representation | ARC may store compressed or decompressed representations; `CacheEntryHeader.memory_domain` distinguishes them |
| #1246 (encryption) | Composition order | Compress-then-encrypt order is mandated; `ExtentLocatorValueV1.encryption_epoch` is set after compression |

## 3. Format Extension Model

### 3.1 Principle: new record types, not modified existing types

Compression extends the on-media format without modifying existing record
payloads. The cardinal rule from v0.262 — "Design-only features must not
change existing payload meanings" — is enforced through two mechanisms:

1. **New record types.** A compressed extent payload uses a distinct record
   type identifier so that readers can mechanically dispatch without
   inspecting the payload body.
2. **Feature flag gating.** A dataset that contains compressed extents
   declares the corresponding feature flag. Readers that do not understand
   the flag are denied mount (incompat) or restricted to read-only
   (ro_compat), depending on the flag's classification.

### 3.2 New record types: EXTENT_DATA_COMPRESSED_V1

The canonical V1 record family catalog (#1220) is extended with one new type:

| Record | family_id | type_id | Description |
|---|---|---|---|
| `EXTENT_DATA_V1` | 1 | 3 | Existing uncompressed extent payload |
| `EXTENT_DATA_COMPRESSED_V1` | 1 | 8 | New: compressed extent payload with per-extent algorithm and logical length |

The `EXTENT_DATA_COMPRESSED_V1` record header carries:

```
ExtentDataCompressedV1 {
    family_id: u16,            // 1 (dataset family)
    type_id: u16,              // 8 (EXTENT_DATA_COMPRESSED_V1)
    record_len: u32,           // total record length including payload
    logical_length: u64,       // uncompressed byte length
    compression_algorithm: u8, // 0x01 = zstd, 0x02 = lz4 (same as frame header)
    flags: u8,                 // bit 0: partial_block_tail (see §5.2)
    reserved: [u8; 14],        // TLV extension anchor
    crc32c: u32,               // CRC32C of fixed prefix (bytes 0..36)
    // payload follows: compressed bytes
}
// Fixed prefix: 36 bytes
```

The `EXTENT_DATA_V1` record continues to carry uncompressed payloads. This
ensures:
- Uncompressed extents remain readable by non-compression-aware implementations
  when the `compat` feature flag is set (see §3.3).
- Readers that do not understand `EXTENT_DATA_COMPRESSED_V1` never encounter
  it because the feature flag gates mount.

### 3.3 Feature flag classification

Two feature flags are defined for compression:

| Canonical name | Class | Mount effect when unknown | Justification |
|---|---|---|---|
| `org.tidefs:compression_lz4` | `ro_compat` | Read-only mount | LZ4-compressed extents cannot be read without LZ4 decompression; writes would produce correct uncompressed extents, so read-only is sufficient |
| `org.tidefs:compression_zstd` | `ro_compat` | Read-only mount | Same reasoning as LZ4: read requires decompressor, write is safe |

If both flags are set, the dataset may contain either LZ4 or ZSTD compressed
extents. A reader must understand both to gain read-write access.

**Why ro_compat, not incompat?** An implementation that does not understand
compression can still safely _write_ new extents — it will use the uncompressed
`EXTENT_DATA_V1` path. It cannot read compressed extents, so read-only is
the correct class. For pure read workloads (e.g., a backup scanner that
only enumerates files), this is sufficient. If writes are needed, the
operator upgrades to a compression-aware build.

**compat future:** If a future compression algorithm is entirely optional
(e.g., a read-only hint that can be silently ignored), it may be classified
as `compat`. Both LZ4 and ZSTD require decompression for correctness and
thus merit `ro_compat`.

### 3.4 Locator table compression field

The `ExtentLocatorValueV1` record (#1285) already carries a `compression`
field:

```
ExtentLocatorValueV1 {
    ...
    compression: u8,            // 0 = none, 1 = zstd, 2-255 = reserved
    logical_length: u64,        // uncompressed byte length
    physical_length: u64,       // bytes on disk
    ...
}
```

This field is the authoritative compression metadata for a stored extent
payload. The `EXTENT_DATA_COMPRESSED_V1` record header repeats the algorithm
for self-describing payloads, but the locator table entry is the canonical
source. The record header's `compression_algorithm` is verified against the
locator table entry on read; a mismatch is a corruption error.

### 3.5 Relationship with tidefs-frame

The existing `tidefs-frame::CompressionAlgorithm` enum and 5-byte frame
header (`[algorithm: 1B][uncompressed_len: 4B LE]`) are used at the
object-store level by `tidefs-compression`. At the extent payload level,
the algorithm byte is embedded in the `EXTENT_DATA_COMPRESSED_V1` record
header rather than in a separate frame wrapper, because the extent record
header already provides the framing boundary via `record_len`. The
algorithm values (0x01 = zstd, 0x02 = lz4) are shared between both layers.


## 4. Per-Dataset Compression Policy

### 4.1 Property definitions

Four properties are registered in the unified property framework (#1253):

| Property | Type | Default | Inheritance | Change policy | Feature flag |
|---|---|---|---|---|---|
| `compression` | ENUM(`off`, `lz4`, `zstd`) | `off` | PARENT | ALWAYS | `org.tidefs:compression_lz4` or `org.tidefs:compression_zstd` |
| `compression_level` | U64 (range 0..22) | algorithm-specific | PARENT | ALWAYS | N/A |
| `compression_min_bytes` | SIZE | 4096 | PARENT | ALWAYS | N/A |
| `compression_ratio_threshold` | U64 (percentage 50..100) | 95 | PARENT | ALWAYS | N/A |

**`compression`**: Selects the compression algorithm. `off` disables
compression for the dataset (no feature flag required). `lz4` enables LZ4
(requires `org.tidefs:compression_lz4`). `zstd` enables ZSTD (requires
`org.tidefs:compression_zstd`).

**`compression_level`**: Algorithm-specific compression level. For LZ4:
0 (fast) to 16 (HC). Default: 0. For ZSTD: 1 to 22. Default: 3 (matches
ZFS's ZSTD default). The value is clamped to the algorithm's valid range
at property-set time.

**`compression_min_bytes`**: Extent payloads smaller than this threshold are
stored uncompressed. Default: 4096 (one page). Rationale: compressing a
4 KiB extent typically saves little space (a few hundred bytes at most)
while burning CPU on every read.

**`compression_ratio_threshold`**: If the compressed payload is >= this
percentage of the uncompressed payload, the data is stored uncompressed.
Default: 95 (i.e., if compression saves < 5%, don't bother). This
prevents the pathological case where incompressible data (e.g.,
pre-compressed JPEG or video) is stored with the record header overhead
but no space savings. The check happens at write time on the compressed
output before committing.

### 4.2 Property inheritance

With `InheritanceMode::PARENT`, compression properties propagate down the
dataset hierarchy. Setting `compression=lz4` on the pool root enables LZ4
compression for all datasets unless a child overrides it. Example:

```
pool-root:        compression=zstd  (set explicitly)
  ├── home:       compression=lz4   (overridden: faster for interactive workloads)
  ├── media:      (inherits zstd)
  └── backups:    compression=off   (overridden: already compressed data)
```

The effective compression policy for a dataset is resolved at dataset-open
time by walking the parent chain. The resolved values are cached in the

### 4.3 Property change semantics

`ChangePolicy::ALWAYS` means compression properties can be changed at any
time on a live dataset. The change takes effect for the next write operation;
existing extent payloads are not recompressed. This is the same model as
ZFS: changing `compression` does not trigger a recompression pass. Existing
extents retain their original compression.

A future `tidefsctl dataset recompress` command could walk extent maps and
recompress payloads to the current policy, but that is deferred.

### 4.4 Feature flag gating

Setting `compression` to `lz4` or `zstd` requires the corresponding feature
flag to be enabled on the dataset. If the flag is not enabled, the property
set is rejected with an error. The flag must be enabled before the property
is set:

```
tidefsctl dataset enable-feature <dataset> org.tidefs:compression_zstd
tidefsctl dataset set <dataset> compression=zstd
tidefsctl dataset set <dataset> compression_level=5
```

## 5. Per-Extent Override

### 5.1 Incompressible data detection

Some payloads are inherently incompressible (pre-compressed media,
encrypted data, random binary). Writing them with compression enabled
wastes CPU and may _increase_ storage size due to record header overhead.

At write time, the compression engine:

1. Compresses the payload using the dataset's configured algorithm and level.
2. Compares `compressed_len + 36` (record header) against
   `uncompressed_len + EXTENT_DATA_V1_HEADER_SIZE`.
3. If the ratio exceeds `compression_ratio_threshold` (default 95%), the
   compressed data is discarded and the payload is stored as an uncompressed
   `EXTENT_DATA_V1` record.

This is an automatic per-extent override: the dataset policy says "use ZSTD,"
but the write path detects incompressibility and stores uncompressed.

### 5.2 Application-level hints (future)

A future extension may allow applications to hint that specific byte ranges
are incompressible via `fcntl(F_SETFL, O_COMPRESSED)` or an `ioctl`. The
hint would be carried as a flag in the extent map entry. This is deferred
until a performance use case emerges.


## 6. Block Alignment and Read-Modify-Write

### 6.1 Alignment constraint

Compression and decompression operate on aligned block boundaries. The
alignment unit is the dataset's `recordsize` (#1183, default 128 KiB).
A compressed extent payload is an integer number of logical blocks.

This constraint exists because:
- Random reads into a compressed extent require decompression from the
  start of the block boundary.
- Partial-block writes (sub-recordsize writes) into a compressed extent
  require read-modify-write.

### 6.2 Partial-block write into a compressed extent

When a write modifies fewer bytes than the recordsize within an existing
compressed extent:

```
// Given: compressed extent covering [0, 128K)
// Write: 4K at offset 32K

1. Read the full 128K compressed extent from the locator table.
2. Decompress to a temporary buffer (128K uncompressed).
3. Overwrite bytes [32K, 36K) with the new data.
4. Recompress the modified buffer.
5. If the new compressed payload fits within the original physical_length:
   a. Write it back to the same physical location (in-place update).
   b. Update the locator table entry's checksum and logical_length.
   c. The extent map entry is unchanged (same logical_offset and length).
6. If the new payload exceeds the original physical_length:
   a. Allocate new physical space via the allocator.
   b. Write the new compressed payload.
   c. Create a new locator table entry (new locator_id, new physical_offset).
   d. Update the extent map entry to point to the new locator_id.
   e. Decrement the old locator's refcount.
```

The read-modify-write path is slower than a fresh write to an uncompressed
extent. The `compression_min_bytes` threshold helps here: small files
(below recordsize) are never compressed, so partial-block writes on small
files avoid the RMW penalty.

### 6.3 O_DIRECT alignment interaction

`O_DIRECT` requires I/O buffers to be aligned to the logical block size
(typically 512 bytes) and I/O lengths to be multiples of the block size.
Compression adds a secondary alignment constraint: the I/O must align to
the extent boundary for decompression to be possible.

The block-volume adapter handles this by:
1. Receiving the O_DIRECT request from the kernel.
2. Determining the extent boundaries from the extent map.
3. If the request spans a compressed extent, reading the entire compressed
   extent, decompressing, and copying the O_DIRECT-aligned sub-range.
4. The O_DIRECT alignment (512-byte) is satisfied from the kernel's
   perspective; the internal read of the full compressed extent is an
   implementation detail.

This matches the ZFS behavior where `O_DIRECT` requests may trigger
internal read-modify-write for compressed blocks.

## 7. Integration with Extent Map Tristate Model

### 7.1 Compression scope

Per #1225, the extent map tristate model defines three states: HOLE,
UNWRITTEN, and DATA. Compression applies only to DATA extents:

- **HOLE**: No on-media payload exists. Nothing to compress.
- **UNWRITTEN**: No on-media payload exists (zero-fill on read).
  Nothing to compress.
- **DATA**: Has an on-media payload with a locator table entry. The
  payload may be compressed.

This means the `ExtentMapEntryV2.extent_kind` field is still `0` (DATA)
for compressed extents. The compression metadata is carried in the
locator table entry (`compression` field) and in the payload record
header (`EXTENT_DATA_COMPRESSED_V1.type_id`), not in the extent map.

### 7.2 Extent map flags

The `ExtentMapEntryV2.flags` field reserves bits 1-2 as `compression_hint`:

| bits 1-2 | Meaning |
|---|---|
| 00 | No hint / use dataset policy |
| 01 | Prefer compressed (application hint, future) |
| 10 | Prefer uncompressed (incompressible hint, future) |
| 11 | Reserved |

For v1, these bits are always 00. The compression decision is governed
entirely by the dataset property and the write-time compressibility
check. The flags are reserved for future per-extent or per-file
compression override hints.

### 7.3 Extent mutation with compression

When a compressed DATA extent is partially overwritten or punched:

**punch_hole**: The extent is freed (refcount decremented). Nothing changes
about the compression metadata — the extent is simply gone.

**write into existing DATA**: The old extent is freed (CoW semantics) and a
new extent is created. The new extent follows the current dataset compression
policy, which may differ from the old extent's policy. This is correct:
if the dataset's `compression` was changed from `zstd` to `lz4`, new writes
use LZ4 while old extents remain ZSTD-compressed.

**truncate shrink**: Extents past the new EOF are freed. No recompression.

**fallocate / zero_range**: Creates UNWRITTEN extents. No compression.


## 8. Space Accounting

### 8.1 Logical vs physical double-book

Compression creates a divergence between logical space (what users see via
`statfs` and what `st_blocks` reports) and physical space (what the
allocator manages). The space accounting model (#1215) is extended with
new counters:

```
DatasetSpaceCountersV1 {
    logical_used_bytes: u64,            // Uncompressed bytes (unchanged)
    physical_used_bytes: u64,           // NEW: on-disk compressed bytes
    pinned_snapshot_bytes: u64,
    reserved_bytes: u64,
    orphan_bytes: u64,
    quota_bytes: u64,
    slop_bytes: u64,
    compression_savings_bytes: u64,     // NEW: logical_used - physical_used
}
```

**`physical_used_bytes`** tracks the actual on-disk bytes consumed by this
dataset's extents, including record header overhead and compression
framing. This is what the allocator sees: when physical space is low,
this counter (not logical_used) determines whether writes block.

**`compression_savings_bytes`** is derived: `logical_used_bytes - physical_used_bytes`.
It is informational for operators and dashboards.

### 8.2 statfs reporting

`statfs` reports logical space, not physical. The user sees:

```
Filesystem    Size  Used  Avail  Use%
tidefs/pool   100G   30G    70G   30%
```

The "Used" is `logical_used_bytes` (what users think they've stored).
The "Avail" is derived from `logical_avail_bytes` from the space accounting
model. This is the correct POSIX behavior, matching ZFS.

### 8.3 SpaceDelta extensions

The `SpaceDelta` accumulator (#1215) is extended for compression:

```
SpaceDelta {
    logical_used_delta: i64,
    physical_used_delta: i64,           // NEW
    reserved_delta: i64,
    orphan_delta: i64,
    pinned_snapshot_delta: i64,
    compression_savings_delta: i64,     // NEW
}
```

On every extent write, the delta carries:
- `logical_used_delta = +uncompressed_len`
- `physical_used_delta = +compressed_len + record_header_overhead`
- `compression_savings_delta = +(uncompressed_len - compressed_len - overhead)`

On every extent free, the deltas are negated.

### 8.4 Quota enforcement

Quotas are enforced against `logical_used_bytes`, not `physical_used_bytes`.
This matches ZFS behavior: a compression-enabled dataset with a 100 GB
quota can store more than 100 GB of user data if the data compresses well.
The quota reflects the user's view, not the disk's view.

## 9. Cache Implications

### 9.1 Compressed vs decompressed representation

The weighted ARC cache (#1192) stores extent data entries. With compression,
the cache must decide whether to store the compressed or decompressed
representation.

**Default: decompressed.** The ARC stores decompressed payloads. This is
the simpler model and matches the demand-paging pattern: reads typically
need the decompressed bytes anyway, and decompression-on-insert is a
one-time cost amortized over subsequent cache hits.

**Compressed representation option (deferred):** For very large caches
with high hit rates on compressible data, storing compressed payloads
in the ARC and decompressing on each hit may increase effective cache
capacity. This is an optimization deferred to the cache-device tiering
design (#1256).

### 9.2 ARC admission weighting

The weighted ARC (#1192) measures capacity in bytes, not entry count.
With compression, the admission weight for a decompressed cached entry
is `uncompressed_len` (the memory it occupies), not `compressed_len` (the
physical bytes it came from). This is correct: the ARC budget is
measured in resident memory bytes.

The compression ratio is available as a hint for admission policy:

```
admission_weight = uncompressed_len
compression_savings_ratio = 1.0 - (compressed_len / uncompressed_len)
```

If the ARC is near capacity and a new entry must be admitted, the eviction
algorithm may optionally favor retaining entries with high
`compression_savings_ratio` — these represent more logical data per physical
byte and are thus more "valuable" to keep. This is a soft policy hint,
not a correctness requirement.

### 9.3 Demand-must-win rule

The "demand must win" rule from #1192 means that a demand read (synchronous
application I/O) never blocks on cache admission. If the ARC is full and
a demand read arrives:

1. The read's payload is decompressed into a temporary buffer.
2. ARC eviction runs in parallel (background or best-effort).
3. If eviction succeeds before the read returns, the entry is inserted.
4. If eviction would block the demand read, the entry is served directly
   from the temporary buffer without cache insertion.

This ensures that decompression cost does not compound with cache pressure
to create latency spikes for demand I/O.


## 10. Algorithm Candidates and Selection

### 10.1 LZ4 — baseline fast compression

| Property | Value |
|---|---|
| Algorithm byte | 0x02 |
| Feature flag | `org.tidefs:compression_lz4` |
| Compression levels | 0 (fast) to 16 (HC) |
| Default level | 0 |
| Typical ratio | 1.5-2.5x on text/logs |
| Typical throughput | 400-800 MB/s per core (compress), 2-4 GB/s (decompress) |
| Crate | `lz4_flex` (pure Rust, no unsafe) |

LZ4 is the baseline algorithm. It is extremely fast (faster than most
NVMe drives can write), provides reasonable compression on structured
and textual data, and has a well-tested pure Rust implementation. It
is the recommended default for general-purpose workloads where I/O
latency matters more than space efficiency.

### 10.2 ZSTD — high-compression option

| Property | Value |
|---|---|
| Algorithm byte | 0x01 |
| Feature flag | `org.tidefs:compression_zstd` |
| Compression levels | 1 to 22 |
| Default level | 3 (matches ZFS default) |
| Typical ratio | 2-5x on text/logs |
| Typical throughput | 50-400 MB/s per core (compress, level-dependent), 1-2 GB/s (decompress) |
| Crate | `zstd` (bindings to facebook/zstd C library) |

ZSTD provides significantly better compression ratios than LZ4 at the
cost of higher CPU usage during compression. Decompression throughput
remains high (comparable to LZ4 in many cases). ZSTD is recommended for:

- Archival and backup datasets (write-once, read-rarely)
- Log aggregation datasets (highly compressible, large volumes)
- Container image registries (many small, similar files)
- Any dataset where storage cost dominates CPU cost

### 10.3 Future algorithms

The algorithm byte space reserves values 0x03-0xFF. Future candidates include:

- ZSTD with pre-trained dictionaries (0x03)
- LZ4 HC with higher levels (already covered by LZ4 level > 0)
- Brotli (0x04)

Each new algorithm requires a new feature flag, ENUM variant, algorithm
byte value, and integration into `tidefs-frame`.

## 11. Compress-then-Encrypt Ordering

### 11.1 Compress before encrypt

Compression must be applied _before_ encryption. This is the industry
standard for two reasons:

1. **Encrypted data is incompressible.** Good encryption produces output
   that is indistinguishable from random data. Compressing after encryption
   is a waste of CPU and may _increase_ output size.
2. **CRIME/BREACH attack surface.** Compressing after encryption can leak
   information about plaintext through the compressed output size, enabling
   chosen-plaintext attacks. Compress-then-encrypt avoids this.

The composition order for a compressed, encrypted extent is:

```
plaintext → compress (LZ4/ZSTD) → encrypt → EXTENT_DATA_COMPRESSED_V1 → write
```

On read, the order is reversed:

```
read → EXTENT_DATA_COMPRESSED_V1 → decrypt → decompress → plaintext
```

### 11.2 Encryption of compression metadata

The compression algorithm byte in the `EXTENT_DATA_COMPRESSED_V1` record
header and in the `ExtentLocatorValueV1.compression` field are stored in
plaintext. This allows the storage layer to identify compressed extents
without accessing encryption keys. The actual extent payload (compressed
bytes) is encrypted. This matches the ZFS approach.

## 12. Implementation Plan

### Phase 1: Feature flags and record type registration
- Define `org.tidefs:compression_lz4` and `org.tidefs:compression_zstd` in the
  feature name registry (#1223).
- Add `EXTENT_DATA_COMPRESSED_V1` (`family=1, type=8`) to the canonical
  record family catalog (#1220).
- Define the `ExtentDataCompressedV1` Rust struct with encode/decode.

### Phase 2: Dataset properties
- Register compression properties in the property registry (#1253).
- Implement property resolution (PARENT inheritance) for compression.
- Feature flag gating: setting compression to non-off requires feature flag.

### Phase 3: Extent write path
- Integrate compression into the extent write path in
  `tidefs-local-filesystem`.
- Write-time compressibility check with `compression_ratio_threshold`.
- Write `EXTENT_DATA_COMPRESSED_V1` or fall back to `EXTENT_DATA_V1`.
- Update `ExtentLocatorValueV1.compression` and space accounting deltas.

### Phase 4: Extent read path
- Read `EXTENT_DATA_COMPRESSED_V1`: decompress transparently.
- Verify `compression_algorithm` matches locator table.
- Handle decompression errors (corruption → EIO or read repair).

### Phase 5: Read-modify-write
- Implement partial-block write into compressed extent (RMW path).
- Handle in-place update vs reallocation with space accounting.

### Phase 6: Cache integration
- ARC stores decompressed payloads (default).
- Admission weight: `uncompressed_len`.
- Demand-must-win path: no cache insertion under pressure.

### Phase 7: Feature gating and mount enforcement
- Mount-time check: dataset with unknown compression feature → RO mount.
- Write-time check: disabled compression property → uncompressed writes.

- Full pipeline test: create, enable, write, verify, read back, mixed
  algorithms, quota enforcement, space accounting consistency.



  encode/decode, CRC32C correctness, and field layout.
- `tidefs-xtask check-compression-roundtrip`: compressed extent write/read
  round-trip for LZ4 and ZSTD across multiple payload sizes.
- `tidefs-xtask check-compression-space-accounting`: verifies
  `logical_used_delta`, `physical_used_delta`, `compression_savings_delta`.
- `tidefs-xtask check-compression-feature-gate`: mount-time enforcement:
  unknown compression feature → RO, known feature → RW.
- `tidefs-xtask check-compression-cache`: weighted ARC with compression;
  demand-must-win under pressure; cache insertion ratio.

## 14. Comparison with ZFS

| Aspect | ZFS | TideFS (this design) |
|---|---|---|
| Compression scope | Per-dataset or per-zvol | Per-dataset with per-extent automatic override for incompressible data |
| Algorithm selection | Single algorithm per dataset | Single algorithm per dataset with runtime incompressibility fallback |
| Compression levels | ZSTD 1-19 (default 3); LZ4 always fast | Same level ranges; LZ4 default 0, ZSTD default 3 |
| On-disk representation | Compressed block pointer (`lsize`, `psize`, `comp` in block_ref) | `EXTENT_DATA_COMPRESSED_V1` record + `ExtentLocatorValueV1.compression` |
| Feature flags | Pool-level feature flags | Per-dataset feature flags with ro_compat classification |
| Property inheritance | ZFS property inheritance (PARENT) | Same PARENT inheritance via unified property framework |
| Read-modify-write | In-place RMW for compressed blocks | Same: read full compressed extent, modify, recompress |
| Cache | ARC stores decompressed; FlashTier may store compressed | ARC stores decompressed (default); optional compressed for FlashTier (deferred) |
| Space accounting | `USED` = logical; `LUSED`/`PSIZE` in zpool list | `logical_used_bytes` for statfs; `physical_used_bytes` for allocator |
| Compress-then-encrypt | Yes, enforced | Same, enforced |
| Metadata compression | Yes (indirect blocks, object_nodes) | Deferred: only extent payloads in v1 |

## 15. Non-claims (explicit boundaries)

- This design does not extend compression to metadata records (inodes,
  directory entries, dataset records, extent maps). Metadata compression
  is a separate concern.
- This design does not implement recompression of existing extents when
  the dataset compression property changes.
- This design does not implement compressed representation in the ARC.
  ARC stores decompressed payloads by default; compressed ARC entries are
  deferred to #1256.
- This design does not implement per-file or per-extent compression
  override hints from applications.
- This design does not implement ZSTD dictionary training or pre-trained
  dictionaries. Algorithm byte 0x03 is reserved.
- This design does not modify the `tidefs-compression` crate's per-object
  compression semantics. The object-store and extent-payload compression
  layers are independent and may coexist.
- This design does not implement the `tidefsctl dataset recompress` command.
## 16. Current Implementation Status (live authority trace)

This section traces the actual live compression authority for mounted
filesystem content writes as of the current `origin/master`. It answers
exactly which code path consumes the per-dataset policy and which
crates/surfaces are lower-tier helpers or property-library artifacts
that do not directly govern mounted writes.

### 16.1 Live authority chain

The mounted content write path follows this chain:

```
tidefsctl dataset set-strategy
  -> FeatureFlags (persisted in pool store)
  -> DatasetFeatureFlags::load() at mount time
  -> resolve_compression_policy(&feature_flags)  [lib.rs:674]
  -> ContentCompressionPolicy { algorithm, level, min_savings_bytes }
  -> stored in LocalFileSystemOpenedState.content_compression_policy
  -> passed to every write_chunked_content / write_chunked_content_with_overlay
  -> encode_content_chunk(record, chunk_index, bytes, &policy)
```

Policy refresh at runtime (without remount):

```
tidefsctl dataset set-strategy (live mutation)
  -> LocalFileSystem::persist_feature_flags()
  -> LocalFileSystem::refresh_policies_from_features()
  -> content_compression_policy updated in-memory
  -> next write uses the new policy
```

### 16.2 What is live

| Surface | Status | Authority |
|---|---|---|
| `resolve_compression_policy` (lib.rs:674) | Live | Reads `FeatureFlags` for `FEATURE_COMPRESSION_LZ4` / `FEATURE_COMPRESSION_ZSTD`; returns Zstd/Lz4/Off policy with priority Lz4 > Zstd > Off. |
| `ContentCompressionPolicy` (types.rs:1957) | Live | Three variants (None, Zstd, Lz4) with per-variant level and min-savings threshold. |
| `encode_content_chunk` (encoding.rs:1134) | Live | Applies algorithm from policy; threshold-gates at `min_savings_bytes`; falls back to uncompressed when savings are insufficient. |
| `write_chunked_content` / `write_chunked_content_with_overlay` (content.rs) | Live | All mounted content write paths consume `compression_policy` and pass it through to `encode_content_chunk`. |
| `refresh_policies_from_features` (lib.rs:1200) | Live | Enables live policy changes without remount. |
| `tidefsctl dataset set-strategy` | Live | Operator CLI for enabling/disabling compression features (#6162). |

### 16.3 What remains design-spec (not yet live or not the mounted write authority)

| Surface | Tier | Notes |
|---|---|---|
| `tidefs-compression` crate (`CompressedObjectStore`) | Helper/library | Provides transparent per-object compression at the object-store level. Not consumed by the mounted content write path. The `get_extent`/`put_extent` API around `CompressedExtentPayload` is crate-internal or test-only; the local-filesystem crate does not call it for content chunks. |
| `tidefs-dataset-properties` (`compression.algorithm`) | Property-library surface | Defines registered property metadata with inheritance rules and feature-flag gating. This crate is a property-definition library; it does not directly drive mounted content writes. The live authority is `FeatureFlags` + `resolve_compression_policy`. |
| `tidefs-control-plane-runtime` dataset catalog | Deprecated side-store | Explicitly deprecated by #6162; zero live runtime consumers. |
| `EXTENT_DATA_COMPRESSED_V1` record type | Design only | The content chunk path uses the existing `CONTENT_CHUNK_MAGIC` record with an algorithm byte in the header, not the 36-byte `ExtentDataCompressedV1` prefix from sec.3.2. |
| Per-extent incompressibility detection (sec.5.1) | Future | The `encode_content_chunk` threshold gating applies at the chunk level; per-extent `compression_ratio_threshold` with automatic fallback to `EXTENT_DATA_V1` is not implemented. |
| Read-modify-write into compressed extents (sec.6) | Future | The content-chunk model uses append-only chunks, not in-place RMW. |
| ARC compressed representation (sec.9) | Future | Decompressed-only per sec.9.1 default. |
| Space accounting `physical_used_bytes` (sec.8) | Future | Not yet wired into space accounting deltas. |
| `tidefsctl dataset recompress` | Future | Not implemented. |


- `tidefs-compression` crate: 38 tests covering encode/decode, round-trip, incompressible data, and error cases. These test the helper library, not the mounted write path.
- `tidefs-local-filesystem` `encode_content_chunk` / `decode_content_chunk` round-trip: covered by the proptest in `proptests.rs` using `ContentCompressionPolicy::zstd_default()`.
- `resolve_compression_policy` unit test: added in the same commit as this doc update (see `lib.rs` test module).


## 17. References

- `docs/DATASET_FEATURE_FLAGS_DESIGN.md` — Feature flag architecture (#1223)
- `docs/design/on-media-format-strategy.md` — V1 record family catalog (#1220)
- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` — Tristate extent model (#1225)
- `docs/EXTENT_MAPS_LOCATOR_TABLES_DESIGN.md` — Extent maps and locator tables (#1285)
- `docs/SPACE_ACCOUNTING_MODEL_DESIGN.md` — Space accounting model (#1215)
- `docs/design/weighted-arc-cache-per-entry-weight-tracking.md` — Weighted ARC cache (#1192)
- `crates/tidefs-frame/src/lib.rs` — Compression frame format (5-byte header)
- `crates/tidefs-compression/src/lib.rs` — CompressedObjectStore wrapper
