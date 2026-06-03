# Cache Device Tiering and Second-Level Read Cache (FlashTier) — Design Specification

**Issue**: [#1256](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1256)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1226 (unified cache architecture), #1192 (weighted ARC), #1252 (LOG_DEVICE / intent log), #1241 (lane priority model)
**Related**: #1247 (prefetch architecture), #1229 (BULK plane), #1254 (dedup DDT), #1237 (resource governor)

## Abstract

ZFS's FlashTier (second-level Adaptive Replacement Cache) on fast SSD/NVMe is one of its key
performance features, enabling working sets larger than RAM to be served at near-RAM
speeds. Ceph has cache-tier pools but with complex semantics. tidefs designs cache device
tiering from scratch with the benefit of hindsight: simpler semantics, unified with the
existing cache lattice (#1226), cluster-aware, and with admission control that avoids
ZFS's known FlashTier weaknesses (scan pollution, cold start, no cross-node sharing).

This design introduces three tiers of the read cache hierarchy and the cache device model
that hosts both the FlashTier (read cache) and the log device partition (write cache, per #1252):

```
Level 0: CPU caches (transparent, not managed by tidefs)
Level 1: ARC in RAM (L1ARC)     — #1192, #1226; T1/T2/B1/B2 with byte-weight tracking
Level 2: Cache device (FlashTier)   — this design; NVMe/SSD, persistent, log-structured
Level 3: Pool devices (main)    — authoritative data on pool devices
```

---

## 1. Cache Device Model

### 1.1 Device abstraction

A cache device is a block device (NVMe SSD, SAS SSD, or similar low-latency
high-endurance storage) attached to a pool but distinct from main pool devices.

```
Pool
├── main devices (data + metadata)
│   ├── device-0 (NVMe)
│   ├── device-1 (NVMe)
│   └── device-2 (HDD)
└── cache devices (optional, performance hint)
    ├── cache-dev-0 (NVMe)
    └── cache-dev-1 (NVMe)
```

### 1.2 Invariants

1. **Cache is a performance hint, never correctness-critical** (Principle 2). No
   data in a cache device is authoritative. All cache entries have authoritative
   copies on pool devices.
2. **Cache device failure is survivable.** If a cache device fails, the pool operates
   normally with degraded read performance and no data loss. Write-cache (LOG_DEVICE) entries
   are also non-authoritative — the intent log on cache devices is a secondary fast-path
   copy; the authoritative log lives on pool devices.
3. **Every cache device entry is anchor-bound** (per P4-02 cache taxonomy §1 rule 2).
4. **Cache devices are pool-level, not dataset-level.** Configuration lives in the pool's
   device configuration record.

### 1.3 Device lifecycle operations

| Operation | CLI | Semantics |
|---|---|---|
| Attach cache device | `tidefsctl pool cache-attach <pool> <device>` | Formats device with FlashTier header, begins accepting promotions |
| Replace cache device | `tidefsctl pool cache-replace <pool> <old> <new>` | Detach old, attach new; warm-up from scratch |
| List cache devices | `tidefsctl pool cache-list <pool>` | Shows device path, size, utilization, health |
| Set partition split | `tidefsctl pool cache-split <pool> <read_pct> <write_pct>` | Adjusts FlashTier/LOG_DEVICE partition boundary (online) |

---

## 2. FlashTier Architecture: Second-Level Read Cache

### 2.1 Data flow

```
  ┌──────────────────────────────────────────────────────────────┐
  │                        READ PATH                              │
  │                                                               │
  │  read(object_id, offset, len)                                 │
  │       │                                                       │
  │       ▼                                                       │
  │  ┌─────────┐   hit    ┌──────────────┐                        │
  │  │  L1ARC  │─────────▶│ return data   │                        │
  │  │  (RAM)  │          │ (promote MRU) │                        │
  │  └────┬────┘          └──────────────┘                        │
  │       │ miss                                                 │
  │       ▼                                                      │
  │  ┌──────────┐  hit   ┌──────────────────────────────────┐    │
  │  │  FlashTier   │───────▶│ read from cache device            │    │
  │  │  index   │        │ decompress (LZ4 if applicable)    │    │
  │  │  (RAM)   │        │ promote to L1ARC T1              │    │
  │  └────┬─────┘        │ update FlashTier hit counter          │    │
  │       │              └──────────────────────────────────┘    │
  │       │ miss                                                 │
  │       ▼                                                      │
  │  ┌──────────┐                                                │
  │  │  Pool    │──▶ read from authoritative devices               │
  │  │  devices   │    promote to L1ARC T1                         │
  │  └──────────┘                                                │
  └──────────────────────────────────────────────────────────────┘
```

### 2.2 FlashTier promotion path (write side)

FlashTier is populated on ARC eviction, not on read. This is the critical design
choice inherited from ZFS's FlashTier and preserved here:

1. An entry is evicted from ARC (either T1 or T2 resident list).
2. The evicted entry's key and weight are placed in the corresponding ghost list
   (B1 for T1 evictions, B2 for T2 evictions).
3. The FlashTier admission filter runs: only entries that have been hit while in
   the ghost list (i.e., "would have been a cache hit if still resident") are
   eligible for FlashTier promotion.
4. Eligible entries are queued for asynchronous, batched FlashTier write.
5. FlashTier writes run in the BACKGROUND scheduling lane (#1241) and do NOT block
   ARC eviction — the entry is already evicted from RAM; FlashTier write is best-effort.

```
  ARC eviction
       │
       ▼
  ┌──────────────┐
  │ Ghost list   │──▶ ghost hit occurs ──▶ FlashTier admission filter
  │ (B1 or B2)   │                             │
  └──────────────┘                    ┌────────┴────────┐
                                      │  Admitted?      │
                                      ├─────────────────┤
                                      │ ✓ single-hit?   │──▶ No:  discard
                                      │ ✓ per-dataset?  │──▶ No:  discard
                                      │ ✓ prefetch?     │──▶ Yes: prefetch region
                                      │ ✓ demand read?  │──▶ Yes: FlashTier write queue
                                      └─────────────────┘
                                               │
                                               ▼
                                      ┌──────────────────┐
                                      │ BACKGROUND lane   │
                                      │ batched write     │
                                      │ to cache device   │
                                      └──────────────────┘
```

### 2.3 FlashTier index (in RAM)

The FlashTier index is a small, in-memory mapping from `(object_id, offset, data_version)`
to FlashTier device location. It is the only RAM cost of FlashTier and must be kept
proportional to cache device size.

```rust
/// In-memory index mapping cache keys to on-device locations.
///
/// Budgeted separately from ARC: typically ~1/1000 of FlashTier device size
/// (e.g., 1 GB RAM for 1 TB cache device with 8-byte keys + 16-byte values).
pub struct FlashTierIndex {
    /// Hash table: (object_id, offset, data_version) → FlashTierLocation
    entries: HashMap<FlashTierKey, FlashTierLocation>,

    /// Current index memory footprint (bytes).
    index_bytes: u64,

    /// Maximum index memory budget.
    max_index_bytes: u64,
}

/// Key for FlashTier index lookups.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FlashTierKey {
    pub object_id: u64,
    pub offset: u64,
    pub data_version: u64,
}

/// Location of an entry on the cache device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashTierLocation {
    /// Byte offset within the cache device.
    pub device_offset: u64,
    /// Compressed length of the entry (including header).
    pub compressed_len: u32,
    /// Uncompressed length (for buffer allocation on read).
    pub uncompressed_len: u32,
    /// LZ4-compressed if true, raw otherwise.
    pub compressed: bool,
}
```

---

## 3. FlashTier Admission Control

### 3.1 Ghost-list hit requirement (beats ZFS)

ZFS's FlashTier has a known weakness: sequential scans can pollute the FlashTier by
evicting useful data with single-access scan data. tidefs fixes this:

**Rule**: An entry is FlashTier-eligible only if it was hit at least once while in the
ghost list (B1 or B2). Single-access entries that never receive a ghost hit are
never promoted to FlashTier.

This is enforced by the existing ARC ghost-list hit counters (`b1_hits`, `b2_hits`
in `HotReadCache`). When a ghost hit occurs, the entry's key is moved to the
FlashTier promotion candidate set.

```rust
/// FlashTier admission filter applied during ghost-hit processing.
pub struct FlashTierAdmissionFilter {
    /// Per-dataset FlashTier policy overrides.
    dataset_policies: HashMap<DatasetId, FlashTierDatasetPolicy>,

    /// Promotion candidate set: entries hit in ghost lists,
    /// awaiting batched write to cache device.
    promotion_queue: VecDeque<FlashTierPromotionCandidate>,

    /// Statistics for wear-leveling and admission decisions.
    stats: FlashTierAdmissionStats,
}

#[derive(Clone, Copy, Debug)]
pub enum FlashTierDatasetPolicy {
    /// Default: use ghost-hit admission filter.
    Default,
    /// Never cache this dataset's data in FlashTier.
    /// Used for known streaming workloads, backup targets, etc.
    NoCache,
    /// Always cache in FlashTier (bypass ghost-hit filter).
    /// Used for small, high-value datasets where FlashTier is critical.
    AlwaysCache,
    /// Cache only metadata (indirect blocks, inode data) in FlashTier.
    MetadataOnly,
}
```

### 3.2 Prefetch exclusion

Prefetched data (#1247) is placed in a separate **prefetch-only region** on the
cache device. This region operates as a ring buffer: new prefetch data overwrites
the oldest prefetch data. Prefetch data never evicts demand-read FlashTier data.

The cache device is logically partitioned into three regions:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cache Device Layout                           │
│                                                                  │
│  ┌──────────────┐  ┌──────────────────────┐  ┌───────────────┐  │
│  │  FlashTier       │  │  Prefetch Region     │  │  LOG_DEVICE Region  │  │
│  │  (demand)    │  │  (ring buffer)       │  │  (write cache)│  │
│  │  log-struct. │  │  oldest ←→ newest    │  │  log-struct.  │  │
│  │  append-only │  │                      │  │  append-only  │  │
│  └──────────────┘  └──────────────────────┘  └───────────────┘  │
│      80%                  10%                     10%             │
│  (configurable)     (configurable)         (configurable)        │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Wear-leveling admission throttle

To protect flash endurance, the FlashTier promotion rate is throttled:

```rust
/// FlashTier write throttle for flash wear protection.
pub struct FlashTierWriteThrottle {
    /// Target drive writes per day (DWPD).
    target_dwpd: f64,
    /// Total device capacity (bytes).
    device_capacity_bytes: u64,
    /// Bytes written in current 24-hour window.
    bytes_written_today: u64,
    /// Maximum bytes per second (derived from target_dwpd).
    max_bytes_per_sec: u64,
    /// Token-bucket state for rate limiting.
    tokens: u64,
    last_refill: Instant,
}
```

Target: < 0.1 drive writes per day for consumer SSDs; adjustable for enterprise
NVMe devices with higher endurance ratings.

---

## 4. FlashTier Device Format

### 4.1 Log-structured layout

The FlashTier region is a log-structured, append-only store with periodic trimming.
This design avoids the write amplification of update-in-place and simplifies
crash recovery.

```
FlashTier Device Header (first 4 KiB)
┌──────────────────────────────────────────────────────────────┐
│ magic:            [u8; 4]  = b"L2AC"                         │
│ version:          u32      = 1                               │
│ pool_guid:        u64      matching pool GUID                │
│ device_guid:      u64      unique per cache device           │
│ generation:       u64      incremented on pool commit_group rollback │
│ flash_tier_region_start: u64   byte offset of first log entry    │
│ flash_tier_region_end:   u64   byte offset of region end         │
│ prefetch_region_start: u64                                  │
│ prefetch_region_end:   u64                                  │
│ log_device_region_start:     u64                                  │
│ log_device_region_end:       u64                                  │
│ write_head:       u64      current append position           │
│ trimmed_until:    u64      oldest valid offset               │
│ checksum:         u32      CRC32C of header                  │
│ reserved:         [u8; 3980]                                 │
└──────────────────────────────────────────────────────────────┘
```

### 4.2 FlashTier entry format

Each FlashTier entry is a variable-length record:

```
FlashTier Entry
┌──────────────────────────────────────────────────────────────┐
│ magic:            [u8; 4]  = b"L2EN"                         │
│ entry_length:     u32      total length including header     │
│ object_id:        u64                                         │
│ offset:           u64      byte offset within object         │
│ data_version:     u64      version of authoritative data      │
│ compressed_len:   u32      length of data on device           │
│ uncompressed_len: u32      original length                    │
│ compression:      u8       0=none, 1=LZ4                      │
│ flags:            u8       bit 0: prefetch, bits 1-7: rsvd   │
│ checksum:         u32      CRC32C of data                    │
│ commit_group_birth:        u64      commit_group when this entry was written    │
│ padding:          [u8; 3]                                     │
│ data:             [u8; compressed_len]                        │
└──────────────────────────────────────────────────────────────┘
```

### 4.3 Trimming: circular log


1. The `write_head` advances. When it reaches `flash_tier_region_end`, it wraps to
   `flash_tier_region_start`.
2. Before overwriting, the FlashTier index is scanned to remove entries whose
   `device_offset` falls in the about-to-be-overwritten range.
3. `trimmed_until` is advanced to the new oldest-valid offset.
4. Entries that are overwritten without being re-read are silently lost —
   they simply become FlashTier misses on next access (no correctness impact).

This is simpler than ZFS's FlashTier which has per-entry headers with a separate
free list. tidefs's approach reduces metadata overhead and write amplification.

### 4.4 Compression

FlashTier entries may be compressed with LZ4 to increase effective capacity:

- Compression is optional and configurable per cache device.
- The compression flag in the entry header indicates whether the data is compressed.
- On FlashTier read hit, decompression adds latency but the NVMe read latency
  dominates anyway (typically ~10us read + ~2us LZ4 decompress → still < 20us).
- Compression is applied at promotion time, never blocking the ARC eviction path.

---

## 5. FlashTier Persistence Across Reboots

### 5.1 Persistent log

Unlike early ZFS FlashTier (which required cold warm-up after every reboot), tidefs's
FlashTier persists across reboots from day one:

1. The FlashTier device retains its log across reboots.
2. On pool import, the header's `generation` is compared against the pool's
   current commit_group.
3. If `pool.current_commit_group >= flash_tier_header.generation`:
   - The FlashTier is valid → the in-memory index is rebuilt by scanning the log
     from `trimmed_until` to `write_head`.
4. If `pool.current_commit_group < flash_tier_header.generation`:
     counter is bumped in the header to force a clean start).
5. No "warm-up" period after reboot — the FlashTier is immediately usable.

### 5.2 Index rebuild

Rebuilding the in-memory index from the on-device log:

```rust
impl FlashTierIndex {
    /// Rebuild the in-memory index by scanning the device log.
    ///
    /// Called on pool import after verifying the generation counter.
    /// Entries older than `trimmed_until` or with `commit_group_birth` after a known
    /// rollback are skipped.
    pub fn rebuild_from_device(
        &mut self,
        device: &CacheDevice,
        header: &FlashTierDeviceHeader,
        pool_current_commit_group: u64,
        known_rollback_commit_group: Option<u64>,
    ) -> Result<usize, FlashTierError> {
        let mut offset = header.trimmed_until;
        let mut entries_loaded = 0;

        while offset < header.write_head {
            let entry = device.read_entry(offset)?;

            // Skip entries from rolled-back commit_groups.
            if let Some(rollback) = known_rollback_commit_group {
                if entry.commit_group_birth >= rollback {
                    offset = offset.saturating_add(entry.entry_length as u64);
                    continue;
                }
            }

            if self.index_bytes + FlashTier_KEY_VALUE_BYTES <= self.max_index_bytes {
                self.entries.insert(
                    FlashTierKey {
                        object_id: entry.object_id,
                        offset: entry.offset,
                        data_version: entry.data_version,
                    },
                    FlashTierLocation {
                        device_offset: offset,
                        compressed_len: entry.compressed_len,
                        uncompressed_len: entry.uncompressed_len,
                        compressed: entry.compression == 1,
                    },
                );
                self.index_bytes += FlashTier_KEY_VALUE_BYTES;
                entries_loaded += 1;
            } else {
                // Index budget exhausted — stop loading.
                // Remaining entries on device are effectively orphaned
                // (will be overwritten when write_head wraps).
                break;
            }

            offset = offset.saturating_add(entry.entry_length as u64);
        }

        Ok(entries_loaded)
    }
}
```

---

## 6. Writeback Cache Device (LOG_DEVICE Partition)

### 6.1 Shared device, separate regions

The same physical cache device can serve both the FlashTier (read cache) and the log device
(write intent log, per #1252). The two functions are separated by a configurable
partition boundary to prevent read cache from starving write cache.

```
┌──────────────────────────────────────────┐
│           Cache Device                    │
│                                           │
│  ┌─────────────────┐  ┌────────────────┐  │
│  │  FlashTier Region   │  │  LOG_DEVICE Region    │  │
│  │  (read cache)   │  │  (write cache)  │  │
│  │  log-structured  │  │  log-structured │  │
│  │  read-heavy      │  │  write-heavy    │  │
│  └─────────────────┘  └────────────────┘  │
│        r%                   w%              │
│      r + w = 100                           │
└──────────────────────────────────────────┘
```

Default split: 80% FlashTier, 20% LOG_DEVICE. Adjustable online via
`tidefsctl pool cache-split <pool> <read_pct> <write_pct>`.

### 6.2 Partition resizing

Resizing the partition boundary is an online operation:

1. If expanding LOG_DEVICE: the FlashTier region shrinks. Entries in the to-be-shrunk area
   are removed from the FlashTier index (they become FlashTier misses).
2. If expanding FlashTier: the log device region shrinks. The LOG_DEVICE trim pointer is advanced
   to the new boundary (entries past the boundary are discarded — they already
   exist in the authoritative commit_group journal on pool devices).
3. Both operations are safe because neither FlashTier nor LOG_DEVICE entries are authoritative.

### 6.3 Separate IO scheduling

Reads from the FlashTier region and writes to the log device region use independent IO
submission queues and lane priorities:

| Operation | Lane class | Priority |
|---|---|---|
| FlashTier read (demand miss fill) | DEMAND | Normal |
| FlashTier write (promotion) | BACKGROUND | Low, droppable |
| LOG_DEVICE write (fsync path) | METADATA | High, latency-sensitive |
| LOG_DEVICE read (crash recovery) | CONTROL | Highest, during import only |
| Prefetch fill | SPECULATIVE | Low, droppable |

The BACKGROUND lane for FlashTier writes ensures that cache promotion never competes
with user-facing DEMAND reads or METADATA fsync writes. This is enforced by the
unified lane scheduler (#1241).

---

## 7. Cache Device Replacement and Failure

### 7.1 Device failure

When a cache device fails (IO error, device removal, media fault):

1. The device is marked `FAULTED` in the pool device tree.
2. All FlashTier index entries for that device are dropped.
3. The LOG_DEVICE region on that device is discarded — the intent log's authoritative
   copy on pool devices provides durability.
4. Read performance degrades: FlashTier hits become FlashTier misses, falling through to
   pool device reads.
5. An observability alert is emitted: `cache_device_faulted{device_guid, pool_guid}`.
6. No data loss. Pool continues operating normally.

### 7.2 Adding a new cache device

```
tidefsctl pool cache-attach <pool> /dev/nvme2n1
```

1. Device is formatted with an FlashTier header (magic, pool GUID, new device GUID).
2. `generation` is set to the pool's current commit_group.
3. The in-memory `CacheDevice` struct is added to the pool's device list.
4. FlashTier promotion begins immediately — ARC evictions start feeding the new device.
5. No immediate performance benefit (the device is empty; must warm up).
6. LOG_DEVICE region is available immediately for fsync writes.

### 7.3 Removing a cache device

```
tidefsctl pool cache-remove <pool> /dev/nvme2n1
```

1. The device is marked for removal.
2. In-flight IO to the device is drained.
3. The FlashTier index entries for that device are dropped.
4. The device is closed and removed from the pool's device list.
5. No data movement needed — all data on the cache device is non-authoritative.
6. Operation completes in O(index entries) time, typically < 100ms.

---

## 8. Cluster FlashTier (Differentiator from ZFS)

### 8.1 Cross-node FlashTier probing

ZFS's FlashTier is local-only — a node can only use its own cache devices. tidefs's
cluster architecture enables cross-node FlashTier:

```
  Node A                          Node B
  ┌──────────┐                    ┌──────────┐
  │ FlashTier    │◄──── RDMA BULK ───│ FlashTier    │
  │ index A  │    (FlashTier hit)     │ index B  │
  │          │                    │          │
  │ cache    │──────────────────▶│ cache    │
  │ dev A    │   data transfer    │ dev B    │
  └──────────┘                    └──────────┘
```

Flow:
1. Node A misses in its own L1ARC and FlashTier.
2. Node A queries peer nodes' FlashTier indices via a lightweight RPC
   (`flash_tier_probe(key) -> bool`).
3. If Node B reports a hit, Node A fetches the data from Node B's cache device
   via the BULK plane (#1229) in RDMA.
4. Fetched data is promoted to Node A's L1ARC (but NOT to Node A's FlashTier —
   that would duplicate the cache entry).
5. If no peer has the data, Node A falls through to authoritative pool read.

### 8.2 Remote FlashTier index protocol

```rust
/// Lightweight FlashTier probe: does a peer have this key in its FlashTier?
///
/// Sent via CONTROL lane on the cluster transport. Response is boolean.
/// The probe is cheap: it's an in-memory hash table lookup on the peer.
pub struct FlashTierProbeRequest {
    /// Pool identifier.
    pub pool_guid: u64,
    /// Keys to probe (batched for efficiency).
    pub keys: Vec<FlashTierKey>,
}

pub struct FlashTierProbeResponse {
    /// For each key in the request: true if present in peer's FlashTier.
    pub hits: Vec<bool>,
    /// Peer's FlashTier device GUID (so the requester knows where to fetch from).
    pub device_guid: u64,
}
```

### 8.3 Cross-node FlashTier fetch

When a peer has the data, the fetch uses the BULK plane:

1. Node A sends `FlashTierFetchRequest { key, device_guid }` to Node B via BULK.
2. Node B reads the entry from its cache device.
3. Node B decompresses (if needed) and streams the data to Node A via RDMA.
4. Node A receives the data and promotes it to L1ARC.

Latency target: < 100us for a cross-node FlashTier hit (RDMA read + NVMe read). This
is faster than a local pool-device read on HDD-backed pools and competitive with
local NVMe pool reads when the data is not in the local FlashTier.

### 8.4 Cross-node dedup cache (DDT L2)

The dedup table (#1254) has DDT entries that map block checksums to on-disk
locations. These entries are small, hot, and benefit from caching:

- DDT L2 entries can live on cache devices.
- A node performing dedup on write can probe peers' FlashTier for DDT entries.
- This turns the cluster into a distributed DDT cache, reducing the need for
  every node to maintain a full in-RAM DDT.

---

## 9. Integration with the Cache Lattice

### 9.1 New memory domain

FlashTier index entries live in a distinct memory domain with its own reclaim policy:

| Domain | ID | Description | Reclaim priority | Reserve eligible |
|---|---|---|---|---|
| `CacheDeviceIndex` | 8 | FlashTier in-memory index: maps keys to device locations | 45 (between `AdapterServingHot` and `ProductServing`) | No |

This is the 9th memory domain, extending the existing 8 in `MemoryDomainId`. The
FlashTier index is evictable under memory pressure (entries are dropped from the index;
the on-device entries become unreachable and are eventually overwritten).

### 9.2 New cache class

FlashTier entries on cache devices constitute a new cache class:

| Class | ID | Domain | Description |
|---|---|---|---|
| `FlashTierDeviceCache` | 9 | `CacheDeviceIndex` | Entries on NVMe/SSD cache devices, indexed by in-RAM FlashTier index |

This is the 10th cache class, extending the existing 9 in `CacheClassId`.

### 9.3 Cache entry header integration

Every FlashTier entry on the device carries a minimal `CacheEntryHeader` (per P4-02)
embedded in the FlashTier entry format:

| Header field | FlashTier usage |
|---|---|
| `cache_class_id` | `FlashTierDeviceCache` (9) |
| `memory_domain_id` | `CacheDeviceIndex` (8) |
| `exactness_class` | `"exact"` (FlashTier entries match authoritative data by data_version) |
| `rebuild_cost_class` | `"expensive"` (pool device read is the rebuild cost) |
| `anchor_vector_ref` | `(pool_guid, commit_group_birth, data_version)` hash |
| `entry_size_bytes` | `compressed_len` |
| `budget_domain_ref` | `"cache_device"` |
| `reserve_guard_class` | `SurplusOnly` (FlashTier entries are disposable) |
| `dirty_state_class` | `Clean` (FlashTier is read-only cache) |
| `evictability_class` | `Standard` |
| `poison_state` | `Clean`; set to `AnchorMismatch` if commit_group/generation check fails |

### 9.4 Relationship to hot_read_cache

The existing `HotReadCache` (ARC in `hot_read_cache.rs`) is the L1ARC. The FlashTier
sits below it:

- ARC evictions feed the FlashTier promotion queue.
- ARC ghost-hit counters (`b1_hits`, `b2_hits`) drive FlashTier admission.
- On FlashTier hit, the data is promoted to ARC T1 (just like a pool read hit).
- The FlashTier index is consulted in the `get()` path between ARC miss and pool
  device read.

### 9.5 New `CacheDevice` type family

```rust
/// A cache device attached to a pool.
pub struct CacheDevice {
    /// Unique identifier for this cache device.
    pub guid: u64,
    /// Backing block device path.
    pub device_path: PathBuf,
    /// Total device capacity (bytes).
    pub capacity_bytes: u64,
    /// On-device header.
    pub header: FlashTierDeviceHeader,
    /// In-memory FlashTier index.
    pub flash_tier_index: FlashTierIndex,
    /// Write throttle for wear protection.
    pub write_throttle: FlashTierWriteThrottle,
    /// Admission filter state.
    pub admission_filter: FlashTierAdmissionFilter,
    /// Current state of the device.
    pub state: CacheDeviceState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheDeviceState {
    /// Device is healthy and accepting IO.
    Online,
    /// Device has IO errors but is still usable (degraded).
    Degraded { error_count: u64 },
    /// Device has failed and been removed from service.
    Faulted,
    /// Device is being removed (draining inflight IO).
    Removing,
}
```

---

## 10. Performance Targets

### 10.1 Latency

| Operation | Target | Notes |
|---|---|---|
| L1ARC hit (RAM) | < 1us | Already achieved by ARC |
| FlashTier index probe (RAM) | < 100ns | Hash table lookup |
| FlashTier hit (NVMe read + decompress) | < 20us | NVMe ~10us + LZ4 decompress ~2us + overhead |
| FlashTier miss → pool device read | < 100us (NVMe pool) / < 10ms (HDD pool) | Falls through to authoritative read |
| Cross-node FlashTier probe | < 50us | CONTROL-lane RPC round-trip |
| Cross-node FlashTier fetch | < 100us | RDMA BULK + remote NVMe read |

### 10.2 Throughput and endurance

| Metric | Target |
|---|---|
| FlashTier promotion rate | Throttled to < 0.1 DWPD for consumer SSDs; configurable per device |
| FlashTier write throughput | Up to 1 GB/s (limited by BACKGROUND lane budget) |
| FlashTier read throughput | Up to NVMe device bandwidth (typically 3-7 GB/s) |
| FlashTier index memory overhead | ~0.1% of cache device size (e.g., 1 GB RAM per 1 TB device) |
| Warm-up time after reboot | 0 (persistent log; usable immediately) |

### 10.3 Observability

| Metric | Description |
|---|---|
| `flash_tier_hits_total` | FlashTier cache hits (demand reads) |
| `flash_tier_misses_total` | FlashTier cache misses |
| `flash_tier_prefetch_hits_total` | Hits in the prefetch region |
| `flash_tier_promotions_total` | Entries promoted from ghost lists to FlashTier |
| `flash_tier_promotions_skipped_admission` | Entries rejected by admission filter |
| `flash_tier_promotions_skipped_throttle` | Entries rejected by write throttle |
| `flash_tier_evictions_total` | Entries trimmed from FlashTier (circular log wrap) |
| `flash_tier_index_entries` | Current number of entries in the in-memory index |
| `flash_tier_index_bytes` | Current memory used by the FlashTier index |
| `flash_tier_device_bytes_used` | Bytes written on the cache device |
| `flash_tier_cross_node_probes_total` | Cluster FlashTier probes sent |
| `flash_tier_cross_node_hits_total` | Cluster FlashTier remote hits |
| `cache_device_errors_total` | IO errors on cache devices |

---

## 11. Non-Claims

This design does not cover:

- **Cache device encryption at rest**: cache device data encryption is deferred
  to the encryption design (#1246).
- **Deduplicated FlashTier**: storing only unique blocks across the FlashTier region to
  increase effective capacity (requires dedup integration per #1254).
- **FlashTier write-ahead logging**: crash-consistent FlashTier metadata updates (the
  append-only log-structured format is crash-tolerant by design, but an explicit
  WAL for the index could improve recovery speed).
- **Tiered cache device classes**: using different device classes (e.g., Optane +
  QLC NAND) with automatic promotion/demotion between them.
- **Cache device hot-spare**: automatic failover to a designated spare cache
  device.
- **FlashTier compression beyond LZ4**: ZSTD or other codecs may be added later if
  the compression ratio justifies the decompression latency.

---

## 12. References

- `crates/tidefs-local-filesystem/src/hot_read_cache.rs` — L1ARC implementation (T1/T2/B1/B2, byte-weight tracking)
- `crates/tidefs-local-filesystem/src/cache_lattice.rs` — P4-02 cache lattice (8 memory domains, 9 cache classes, 18-entry header)
- `crates/tidefs-types-cache-lattice-core/src/lib.rs` — `no_std` cache lattice types
- `docs/CACHE_TAXONOMY_INVARIANTS_P4-02.md` — cache taxonomy and invariants
- `docs/design/cache-lattice-views.md` — cache-lattice views design (#1176)
- `docs/design/intent-log-log_device.md` — LOG_DEVICE / intent log design (#1252)
- `docs/design/unified-scheduling-classes-lane-priority-model.md` — lane priority model (#1241)
- Issue #1226 — unified cache architecture
- Issue #1192 — weighted ARC with byte-weight tracking
- Issue #1247 — prefetch architecture
- Issue #1229 — BULK plane for RDMA data transfer
- Issue #1254 — dedup table (DDT) design
- Megiddo & Modha, "ARC: A Self-Tuning, Low Overhead Replacement Cache", FAST 2003
