# Workload-Adaptive Recordsize and Extent Shaping

Maturity: **design-spec** for online recordsize adjustment,
read-modify-write avoidance heuristics, and multi-extent small-write
coalescing.

This document closes Forgejo issue #1257.

## 1. Motivation

ZFS recordsize is set per-dataset and changing it only affects new writes
— existing data keeps its old recordsize. CephFS uses fixed 4 MiB objects.
Neither adapts to actual workload patterns. tidefs can beat both with
workload-adaptive recordsize that:

- **adjusts per-file** based on observed access patterns,
- **avoids read-modify-write** for small overwrites, and
- **coalesces** small sequential writes into larger extents.

| Concern | ZFS | Ceph | tidefs |
|---------|-----|------|--------|
| Recordsize granularity | Per-dataset | Fixed 4 MiB object | Three-tier: dataset → per-file → per-extent |
| Recordsize changes | New writes only | N/A | Online; all extents adjust progressively |
| RMW on small overwrite | Always (4 KiB → read 128 KiB + rewrite) | N/A | Write-redirection below threshold; RMW above |
| Small-write fragmentation | Sequential-log writes coalesce via ZIL then COMMIT_GROUP | Per-object writes | Per-file coalescing buffer + extent merge at rebake |
| Compression ratio | Fixed recordsize caps ratio | Fixed 4 MiB always good | Adaptive: larger recordsize when compressible |
| Dedup granularity | Fixed to recordsize | Fixed to object size | Adaptive: balances hit-rate vs DDT size |

### Dependency Map

| Design | Relationship |
|--------|-------------|
| #1253 Dataset property framework | `recordsize`, `recordsize_min`, `recordsize_max` are per-dataset properties |
| #1245 Compression | Recordsize × compression tradeoff; bias toward larger when compressible |
| #1254 Dedup | Recordsize affects dedup chunk granularity and DDT size |
| #1225 Extent map tristate | HOLE/UNWRITTEN/DATA states; recordsize constrains DATA extent alignment |
| #1222 Rebake architecture | Coalescing: adjacent small extents merged during rebake |
| #1285 Extent maps + locator tables | Locator table indirection enables sub-extent tracking |
| #1190 Writeback transaction model | Coalescing buffer flush integrates with commit_group commit |
| #1265 Online defrag (BPR) | Defrag can re-pack extents at new recordsize |

## 2. Design Overview

Three core abstractions:

| Abstraction | Responsibility |
|-------------|---------------|
| `RecordsizePolicy` | Three-tier policy: dataset default, per-file adaptive, per-extent override |
| `FileWriteStats` | Per-open-file write-pattern tracking (sequential, random, average size) |
| `CoalescingBuffer` | Per-file small-write accumulator; flush-on-seek and flush-on-full |

The system operates in a feedback loop:

```
write(2) → CoalescingBuffer
               │
               ├─ buffer full OR sync → allocate extent at current_recordsize
               │                              │
               │                              └─ update FileWriteStats
               │                                     │
               │                                     └─ re-evaluate recommended_recordsize
               │
               └─ seek (non-sequential) → flush buffer first
```

## 3. Three-Tier Recordsize Policy

### 3.1 Tier 1 — Per-Dataset Default

```rust
/// Dataset-level recordsize properties.
pub struct DatasetRecordsizeConfig {
    /// Default recordsize for new files (default: 131072 = 128 KiB).
    pub recordsize: u32,

    /// Minimum recordsize allowed (default: 4096 = 4 KiB).
    /// Prevents pathological 512-byte extents.
    pub recordsize_min: u32,

    /// Maximum recordsize allowed (default: 1048576 = 1 MiB).
    /// Caps the adaptive growth to bound RMW penalty.
    pub recordsize_max: u32,
}

impl Default for DatasetRecordsizeConfig {
    fn default() -> Self {
        Self {
            recordsize: 131072,      // 128 KiB
            recordsize_min: 4096,    // 4 KiB
            recordsize_max: 1048576, // 1 MiB
        }
    }
}
```

These are dataset properties managed by the property framework (#1253).
Changing `recordsize` only affects new files and adaptive re-evaluation of
open files; existing extents keep their allocation size.

### 3.2 Tier 2 — Per-File Adaptive

Each open file carries a `FileWriteStats` structure that the daemon
updates on every extent allocation. The adaptive algorithm periodically
re-evaluates `recommended_recordsize` and applies the change on the
next extent allocation.

```rust
/// Per-open-file write-pattern tracking.
pub struct FileWriteStats {
    /// Consecutive sequential writes observed.
    pub sequential_count: u64,

    /// Random-access writes (non-sequential after a seek).
    pub random_count: u64,

    /// Exponential moving average of write size in bytes.
    pub avg_write_size: f32,

    /// Last write offset (for sequential detection).
    pub last_offset: u64,

    /// Current recordsize used for extent allocation.
    pub current_recordsize: u32,

    /// Recommended recordsize from the adaptive algorithm.
    pub recommended_recordsize: u32,

    /// Total bytes written since open.
    pub total_bytes_written: u64,

    /// Total number of writes since open.
    pub write_count: u64,

    /// SMA of seek distance for non-sequential writes.
    pub avg_seek_distance: f32,
}
```

### 3.3 Tier 3 — Per-Extent Override

Individual extents can carry a `recordsize_override` field. This is used
when the adaptive algorithm has changed `recommended_recordsize` mid-file
but existing extents remain at their original allocation size.

```rust
/// Recordsize override stored per extent.
pub struct ExtentRecordsizeHint {
    /// 0 = use file-level recordsize; non-zero = this extent's allocation size.
    pub bytes: u32,
}
```

The hint is advisory for rebake/defrag: when an extent is re-packed,
the hint tells the rebaker what size to target.

## 4. Adaptive Recordsize Algorithm

### 4.1 State Machine

```
                 ┌──────────────────┐
                 │  INITIALIZING    │
                 │  recordsize =    │
                 │  dataset default │
                 └────────┬─────────┘
                          │ first extent allocated
                          ▼
                 ┌──────────────────┐
          ┌──────│   OBSERVING      │◄──────────┐
          │      │   (collecting    │           │
          │      │    stats)        │           │
          │      └────────┬─────────┘           │
          │               │ every N writes or   │
          │               │ every M seconds     │
          │               ▼                     │
          │      ┌──────────────────┐           │
          │      │  RE-EVALUATING   │           │
          │      │  compute new     │           │
          │      │  recommended_    │           │
          │      │  recordsize      │           │
          │      └────────┬─────────┘           │
          │               │                     │
          │      ┌────────┴─────────┐           │
          │      ▼                  ▼           │
          │ ┌──────────┐    ┌──────────────┐    │
          │ │ STABLE   │    │ ADJUSTING    │    │
          │ │ no change│    │ apply new    │    │
          │ │ needed   │    │ recordsize   │────┘
          │ └──────────┘    └──────────────┘
          │
          └──────────────────────────────────────
```

### 4.2 Heuristics

The algorithm uses a weighted scoring function:

```
write_pattern_score = w_seq * P(sequential) + w_rand * P(random) + w_mixed * P(mixed)

where:
  P(sequential) = sequential_count / (sequential_count + random_count + 1)
  P(random)     = random_count / (sequential_count + random_count + 1)
  P(mixed)      = 1.0 - P(sequential) - P(random)

  w_seq  =  0.6   (bias toward larger recordsize)
  w_rand = -0.4   (bias toward smaller recordsize)
  w_mixed=  0.0   (neutral)
```

The recommended recordsize is then:

```
recommended_recordsize = clamp(
    current_recordsize * (1.0 + write_pattern_score * step),
    recordsize_min,
    recordsize_max
)
rounded up to the nearest power-of-two within [recordsize_min, recordsize_max]
```

**Step size** (`step`): 0.25 (25% adjustment per re-evaluation).
This damps oscillation: a file must sustain a pattern for several
re-evaluation cycles before the recordsize reaches the limit.

### 4.3 Pattern Classification

| Pattern | Condition | Action |
|---------|-----------|--------|
| **Sequential streaming** | `sequential_count >= 8` consecutive sequential writes | Grow recordsize toward `recordsize_max` (up to 1 MiB) |
| **Random overwrites** | `random_count/(total+1) > 0.7` and `avg_write_size < recordsize/4` | Shrink recordsize toward `recordsize_min` (down to 4 KiB) |
| **Mixed workload** | Neither sequential nor random dominates | Stabilize at weighted average of `avg_write_size` rounded to power-of-two |
| **Database WAL** | File name matches `*.wal`, `*.journal`, write size < 32 KiB, sequential | Lock at `recordsize_min` (4 KiB) |
| **VM image** | File extension matches `*.qcow2`, `*.vmdk`, `*.vdi`, `*.raw`, write size large (>= 64 KiB), mixed | Lock at `recordsize_max` (1 MiB) |
| **Large media** | File size > 1 GiB, sequential, write size >= 256 KiB | Lock at `recordsize_max` (1 MiB) |

### 4.4 Anti-Oscillation

To prevent rapid recordsize cycling:

- **Re-evaluation interval**: minimum 32 writes or 5 seconds since last adjustment.
- **Hysteresis band**: a change is only applied if `|recommended - current| > current/8` (12.5% threshold).
- **Damping**: the `step` factor (0.25) means three consecutive "grow" signals are needed to double recordsize.
- **Cool-down**: after adjusting upward, the algorithm cannot adjust downward for `cooldown_writes` (default: 64 writes). After adjusting downward, the algorithm cannot adjust upward for `cooldown_writes` as well.

### 4.5 Known File-Type Hints

The daemon may accept hints from higher layers (FUSE, NFS, SMB) about
expected workload:

```rust
pub enum FileTypeHint {
    Unknown,
    DatabaseWal,       // SQLite WAL, RocksDB WAL: small sequential → small recordsize
    DatabaseTable,     // SQLite DB, RocksDB SST: random overwrites → medium recordsize
    VirtualMachine,    // qcow2, vmdk: large mixed → large recordsize
    MediaStreaming,    // video, audio: sequential read-heavy → large recordsize
    LogFile,           // application logs: append-only sequential → medium-to-large recordsize
    ContainerImage,    // tar, OCI layers: sequential write-once → large recordsize
    SmallFile,         // < recordsize_min: inline, no extent allocation
}
```

Hints override the adaptive heuristics but are themselves overridden by
explicit per-extent override (Tier 3).

## 5. RMW Avoidance

### 5.1 The RMW Problem

ZFS's well-known RMW penalty: a 4 KiB overwrite in a 128 KiB block:

1. Read 128 KiB from disk
2. Modify 4 KiB in memory
3. Compute new checksum over 128 KiB
4. Write 128 KiB to new location (CoW)

The write amplification is 32:1 (128 KiB written for 4 KiB of user data).

### 5.2 tidefs Solutions

#### 5.2.1 Write Re-direction

When an overwrite covers less than the RMW threshold of the target extent,
the new data is written to a **new, small extent** instead of performing RMW:

```
Before:  [████████████████████████████████]  128 KiB extent
          └──────── logical byte range ───────┘

Overwrite 4 KiB at offset 32 KiB:

After:   [████████][■■■■][████████████████████]  3 extents
          32 KiB    4 KiB   92 KiB
          old DATA  new small  old DATA (new locator)
```

The old extent is split into prefix and suffix DATA extents, each with a
new extent_id/locator (CoW semantics). The overwritten 4 KiB becomes a
separate small extent. The old 128 KiB physical extent is refcount-decremented
and reclaimed when refcount reaches zero.

#### 5.2.2 Sub-Extent Tracking

An extent map entry can point to a sub-range of a physical extent:

```rust
/// A physical extent reference may cover only a sub-range.
pub struct SubExtentRef {
    /// The extent_id of the backing physical extent.
    pub extent_id: ExtentId,
    /// Byte offset within the physical extent.
    pub sub_offset: u64,
    /// Byte length of the sub-range (≤ physical extent length).
    pub sub_length: u64,
}
```

This allows multiple small logical extents to share one physical extent
without RMW. For example, three 4 KiB overwrites within a 128 KiB extent
can all reference sub-ranges of the original physical extent, with only
the dirty 4 KiB regions re-written separately.

#### 5.2.3 RMW Threshold

RMW is only used when the overwrite covers more than the threshold fraction
of the target extent:

```
use_rmw = (overwrite_length >= existing_extent.length * RMW_THRESHOLD)

RMW_THRESHOLD = 0.50  // 50% — configurable per dataset
```

| Overwrite size (128 KiB extent) | Strategy | Write amplification |
|---|---|---|
| 4 KiB | Write-redirect to new small extent | 1:1 (4 KiB → 4 KiB) |
| 32 KiB | Write-redirect to new small extent | 1:1 (32 KiB → 32 KiB) |
| 64 KiB (= 50%) | RMW: read 128 KiB, write 128 KiB | 2:1 |
| 96 KiB | RMW: read 128 KiB, write 128 KiB | 1.33:1 |
| 128 KiB (full) | Full overwrite: no RMW needed; just allocate new 128 KiB | 1:1 |

#### 5.2.4 Coalescing at Rebake

During rebake (#1222), multiple adjacent small extents created by write
re-direction are merged into a single larger extent:

```
Before rebake:
  [32 KiB DATA] [4 KiB small DATA] [92 KiB DATA]

After rebake:
  [128 KiB DATA]  // single contiguous extent
```

This prevents long-term fragmentation from write re-direction.

### 5.3 Decision Flow

```
write(offset, data)
  │
  ├─ offset aligns to recordsize AND length == recordsize
  │    → Full overwrite: allocate new extent, swap locator
  │
  ├─ offset + length spans whole existing extent
  │    → Full overwrite (same as above)
  │
  ├─ length >= existing_extent.length * RMW_THRESHOLD
  │    → RMW: read extent, modify, write new extent, swap locator
  │
  └─ else
       → Write-redirect: write data to new small extent,
         split old extent into prefix/suffix, insert new entry
```

## 6. Small-Write Coalescing

### 6.1 Coalescing Buffer

Each open file has an optional `CoalescingBuffer`:

```rust
/// Per-file small-write coalescing buffer.
pub struct CoalescingBuffer {
    /// Buffered bytes, in order of arrival.
    pub buffer: Vec<u8>,

    /// Logical offset of the first byte in the buffer.
    pub start_offset: u64,

    /// Expected next write offset (for sequential detection).
    pub expected_next: u64,

    /// Maximum buffer size = current_recordsize.
    pub max_size: u32,

    /// Small-write threshold: writes smaller than this are buffered.
    pub small_write_threshold: u32,
}
```

### 6.2 Flush Triggers

| Trigger | Action |
|---------|--------|
| **Buffer full** (`buffer.len() >= max_size`) | Flush buffer as one extent of `min(recordsize, buffered_bytes)` |
| **Sync** (`fsync`, `fdatasync`, `sync`, commit_group commit) | Flush buffer to ensure durability |
| **Seek** (non-sequential write: `offset != expected_next`) | Flush buffer before servicing the seek |
| **Close** (`close`, `release`) | Flush buffer |
| **File size threshold** (file grows past configurable limit) | Flush and optionally switch to larger recordsize |

### 6.3 Buffer Lifecycle

```
write(0, 1 KiB)   → buffer: [1 KiB @ 0],    expected_next: 1024
write(1024, 2 KiB) → buffer: [3 KiB @ 0],    expected_next: 3072
write(3072, 1 KiB) → buffer: [4 KiB @ 0],    expected_next: 4096
write(4096, 512 B) → buffer: [4.5 KiB @ 0],  expected_next: 4608
...
write(130048, ...) → buffer: [128 KiB @ 0] → FLUSH: allocate 128 KiB extent
```

### 6.4 Small-Write Threshold

A write is considered "small" if its length is less than `recordsize / 4`:

```
small_write_threshold = current_recordsize / 4

// For 128 KiB recordsize: writes < 32 KiB are buffered
// For 4 KiB recordsize:   writes < 1 KiB are buffered
```

Writes at or above the threshold bypass the coalescing buffer and are
allocated as immediate extents (padded to the current recordsize).

### 6.5 Interaction with Writeback

The coalescing buffer lives in the FUSE daemon's per-file state. On commit_group
commit (#1190), dirty buffers are flushed:

1. `CoalescingBuffer::flush()` produces one or more `ExtentMapEntryV2`
2. Entries are inserted into the file's `PolymorphicExtentMap`
3. Physical allocation goes through the normal write path
4. `FileWriteStats` is updated with the flushed write size and offset
5. `DirtySet::record_data_write()` accounts the padded bytes

## 7. Recordsize × Compression Interaction

### 7.1 The Tradeoff

- **Larger recordsize → better compression ratio**: more data for the
  compressor to find patterns in (higher LZ4/ZSTD window utilization).
- **Larger recordsize → larger RMW penalty**: a 4 KiB overwrite in a
  1 MiB compressed extent must decompress 1 MiB, modify 4 KiB, recompress
  1 MiB, and compute a new checksum.

### 7.2 Adaptive Bias for Compressed Datasets

When compression is enabled on the dataset (#1245):

```
compression_bias = 1.0 + (compression_ratio - 1.0) * 0.5
// compression_ratio = uncompressed_size / compressed_size
// If ratio = 3.0 (3:1), bias = 2.0 → recordsize grows 2x faster
// If ratio < 1.2 (barely compressible), bias ≈ 1.0 → no change

effective_score = write_pattern_score * compression_bias
```

The bias is applied to the growth direction only; it does not accelerate
shrink. This means compressible data gets larger recordsize (better ratio),
while incompressible data sticks closer to the pattern-based recommendation.

### 7.3 Minimum Recordsize Under Compression

Compression has overhead (dictionary headers, block headers). Below a
certain recordsize, compression can actually **increase** on-disk size:

```
compression_min_recordsize = max(recordsize_min, 4096)
// For ZSTD: minimum 4 KiB to amortize frame headers
// For LZ4:  minimum 4 KiB is adequate
```

The adaptive algorithm never recommends a recordsize below the
compression-aware minimum when compression is enabled.

## 8. Recordsize × Dedup Interaction

### 8.1 The Tradeoff

- **Smaller recordsize → finer-grained dedup**: more chunks to find
  duplicates, higher potential space savings.
- **Smaller recordsize → larger DDT**: the dedup table (#1254) stores
  one entry per extent-aligned chunk. Halving the recordsize doubles
  the DDT entries for the same data.

### 8.2 Adaptive Bias for Dedup-Enabled Datasets

When dedup is enabled on the dataset (#1254):

```
dedup_bias = 1.0 - min(dedup_hit_rate, 0.5)
// dedup_hit_rate = dedup_hits / dedup_lookups (exponential moving average)
// If hit_rate = 0.00 (no dupes):  bias = 1.0 → no change
// If hit_rate = 0.30 (30% hit):   bias = 0.7 → recordsize shrinks ~30%
// If hit_rate = 0.50+ (≥50% hit): bias = 0.5 → recordsize shrinks by half

effective_score = write_pattern_score * dedup_bias
```

The bias is applied to the shrink direction only; it does not accelerate
growth. High dedup hit rates indicate that a smaller recordsize would
capture more duplicates, so the algorithm biases toward smaller extents.

### 8.3 Dedup Chunk Alignment

All dedup chunk boundaries align to `recordsize`. This means:
- Recordsize=128 KiB: dedup compares 128 KiB chunks → coarse, low DDT overhead
- Recordsize=4 KiB: dedup compares 4 KiB chunks → fine, high DDT overhead

The adaptive algorithm balances this tradeoff using the hit rate as a
feedback signal.

### 8.4 DDT Pressure Guard

If the DDT approaches a configurable memory or size limit, the algorithm
biases back toward larger recordsize to reduce DDT entry count:

```
ddt_pressure = current_ddt_entries / max_ddt_entries
if ddt_pressure > 0.75:
    dedup_bias = min(dedup_bias * 1.5, 1.0)  // reduce shrink bias
```

## 9. Observability

### 9.1 Per-File Stats (Read-Only)

| Stat | Type | Description |
|------|------|-------------|
| `tidefs.file.current_recordsize` | Gauge | Current recordsize for the file |
| `tidefs.file.recommended_recordsize` | Gauge | Algorithm's recommended recordsize |
| `tidefs.file.sequential_count` | Counter | Sequential writes since open |
| `tidefs.file.random_count` | Counter | Random writes since open |
| `tidefs.file.avg_write_size` | Gauge | EMA of write size |
| `tidefs.file.coalesced_bytes` | Counter | Bytes coalesced (not yet flushed) |
| `tidefs.file.coalesced_flushes` | Counter | Number of coalescing buffer flushes |

### 9.2 Global Counters

| Metric | Type | Description |
|--------|------|-------------|
| `tidefs.rmw.count` | Counter | Number of RMW operations performed |
| `tidefs.rmw.bytes_read` | Counter | Bytes read for RMW |
| `tidefs.rmw.bytes_written` | Counter | Bytes written for RMW (amplification) |
| `tidefs.rmw_avoided.count` | Counter | Write-redirections that avoided RMW |
| `tidefs.rmw_avoided.bytes_saved` | Counter | Bytes saved by avoiding RMW |
| `tidefs.recordsize.adjustments` | Counter | Total recordsize adjustments |
| `tidefs.recordsize.grew` | Counter | Recordsize increases |
| `tidefs.recordsize.shrank` | Counter | Recordsize decreases |
| `tidefs.coalesce.flushes` | Counter | Total coalescing buffer flushes |
| `tidefs.coalesce.bytes` | Counter | Total bytes coalesced |
| `tidefs.coalesce.fragments_avoided` | Counter | Extent fragments avoided by coalescing |

### 9.3 Histograms

| Metric | Buckets | Description |
|--------|---------|-------------|
| `tidefs.recordsize.distribution` | [4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M] | Distribution of current recordsizes across open files |
| `tidefs.coalesce.buffer_size` | [128, 256, 512, 1K, 4K, 16K, 64K, 128K] | Coalescing buffer fill at flush time |
| `tidefs.rmw.amplification` | [1.0, 1.5, 2.0, 4.0, 8.0, 16.0, 32.0] | Write amplification ratio for each RMW |

## 10. Property API

### 10.1 Dataset Properties (per #1253)

```
# Get current recordsize config
tidefs dataset get tank/docs recordsize
→ recordsize=128K recordsize_min=4K recordsize_max=1M

# Set recordsize (default for new files)
tidefs dataset set tank/docs recordsize=64K

# Set bounds
tidefs dataset set tank/docs recordsize_min=4K recordsize_max=256K
```

### 10.2 Read-Only File Stats

```
# Show adaptive recordsize state for open files
tidefs file stats /tank/docs/bigfile.mkv
→ current_recordsize=1M
→ recommended_recordsize=1M
→ pattern=sequential (128 consecutive)
→ avg_write_size=512K
→ coalesced_bytes=0
```

## 11. Edge Cases

### 11.1 File Truncation

- Truncation to zero resets `FileWriteStats` and clears `CoalescingBuffer`.
- Truncation to a smaller size drops extents past the new EOF;
  `FileWriteStats` is not reset (pattern continues).

### 11.2 Sparse Files

- `lseek` past EOF + `write` creates a hole. The coalescing buffer does not
  fill holes — the gap is represented as HOLE in the extent map.
- The first block after the hole starts a new coalescing sequence.

### 11.3 Memory-Mapped I/O

- `mmap` writes bypass the coalescing buffer (page cache writeback path).
- The page cache flushes at page granularity (4 KiB). These small flushes
  are handled by the RMW-avoidance path.
- `FileWriteStats` tracks mmap writeback separately from `write(2)`.

### 11.4 Concurrent Writes from Multiple FDs

- Each `struct file` has its own `FileWriteStats` and `CoalescingBuffer`.
- The extent map is shared; concurrent writes may interleave at the extent
  level. This is acceptable: the extent map merge logic already handles
  overlapping writes correctly.

### 11.5 Very Small Files

- Files smaller than `recordsize_min` are stored inline in the inode or
  content manifest (existing `ContentLayout::Inline` path).
- No recordsize tracking or coalescing buffer is allocated.

### 11.6 O_DIRECT

- O_DIRECT writes must be recordsize-aligned and recordsize-multiples.
- They bypass the coalescing buffer entirely.
- `FileWriteStats` is still updated.

## 12. Default Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_RECORDSIZE` | 131072 (128 KiB) | Default dataset recordsize |
| `MIN_RECORDSIZE` | 4096 (4 KiB) | Absolute minimum (1 page) |
| `MAX_RECORDSIZE` | 1048576 (1 MiB) | Absolute maximum |
| `RMW_THRESHOLD` | 0.50 | Fraction of extent that triggers RMW |
| `SMALL_WRITE_FRACTION` | 0.25 | Writes < recordsize/4 are "small" |
| `ADAPTIVE_STEP` | 0.25 | Recordsize adjustment per re-evaluation |
| `RE_EVAL_WRITES` | 32 | Min writes between re-evaluations |
| `RE_EVAL_INTERVAL_S` | 5 | Min seconds between re-evaluations |
| `HYSTERESIS_FRACTION` | 0.125 | Min change fraction to apply adjustment |
| `COOLDOWN_WRITES` | 64 | Writes before opposite-direction adjustment |
| `SEQUENTIAL_THRESHOLD` | 8 | Consecutive sequential writes for streaming classification |
| `COALESCE_BUFFER_MAX` | current_recordsize | Max buffer size per file |

## 13. Integration Points

### 13.1 Write Path Changes

The local filesystem write path (`tidefs-local-filesystem`) gains:

1. `CoalescingBuffer` per open file handle (FUSE daemon state).
2. `FileWriteStats` per open file handle.
3. `FileTypeHint` detection from file name/extension.
4. RMW-vs-redirect decision in `insert_single()` / extent map mutation.

### 13.2 Extent Map Changes

`tidefs-types-extent-map-core` gains:

1. `ExtentRecordsizeHint` field on `ExtentMapEntryV2` (using reserved bytes).

`tidefs-extent-map` gains:

1. RMW-split logic: split extent into prefix/data/suffix when write-redirecting.
2. Sub-extent reference support (extent map entry can reference a sub-range).

### 13.3 Rebake Changes

`RebakeService` (#1222) gains:

1. Coalescing of adjacent small extents into `recommended_recordsize`-sized extents.
2. Respecting `ExtentRecordsizeHint` from the extent map.

### 13.4 Dataset Property Changes

Per #1253, the dataset property framework gains `recordsize`, `recordsize_min`,
and `recordsize_max` properties scoped to the dataset.

## 14. Test Plan

|------------|-------------------|
| Unit: `FileWriteStats` | EMA computation, sequential/random classification, hysteresis |
| Unit: `CoalescingBuffer` | Buffer fill, flush-on-full, flush-on-seek, small-write threshold |
| Unit: RMW decision | Threshold boundary conditions (49% vs 51% of extent), edge cases |
| Unit: Adaptive algorithm | Pattern transitions, anti-oscillation, cooldown, known file-type hints |
| Integration: Write path | Full write → coalesce → flush → extent map update cycle |
| Integration: RMW avoidance | Small overwrites produce expected extent splits, old data readable |
| Integration: Compression bias | Compressible data → recordsize grows faster |
| Integration: Dedup bias | High dedup hit rate → recordsize shrinks |
| Property: CLI | `tidefs dataset get/set recordsize*` works end-to-end |
| Replay: Crash during coalesce | Buffer lost on crash, no corruption, file consistency maintained |
