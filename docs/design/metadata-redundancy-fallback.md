# Metadata Redundancy Fallback: Avoid ZFS Special Device Single-Point-of-Failure

**Issue**: [#1281](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1281)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Depends on**: #1220 (on-media format), #1193 (device layout policies), #1267 (commit_group state machine), #1191 (extent management)
**Maturity**: design-spec — defines the dual-copy metadata redundancy model, degraded-mode read fallback, and pool-import resilience against metadata-device loss.

## Abstract

ZFS special devices (metadata-only devices, typically fast NVMe mirrors) are a
**single point of failure for the entire pool**. If all special device members
fail, the ENTIRE pool is lost — even though all data on the regular data devices
is intact. ZFS cannot fall back to reading metadata from the data devices because
metadata is NOT duplicated there. This is the most dangerous ZFS design flaw
that operators discover only after a catastrophic failure.

tidefs avoids this by design. All metadata records are written to **both** the
metadata journal (fast tier) and the data journal (bulk tier). Metadata device
failure is a performance degradation, not a data-loss event. This document
specifies the dual-copy write protocol, the degraded-mode read fallback, the
pool-import resilience contract, and the operational lifecycle of metadata
devices.

---

## 1. Anti-Pattern Analysis

### 1.1 The ZFS special device trap

In ZFS, `special` devices hold metadata and optionally small-file data. The
metadata allocation classes (`special_small_blocks`) direct metadata writes
exclusively to the special device. Critically:

- Metadata is **never** written to the regular data devices once a special device
  exists.
- If all members of the special device fail (e.g., both NVMe devices in a mirror
  die simultaneously due to firmware bug, power surge, or shared controller
  failure), the pool is **unimportable**.
- The regular data devices contain all the data blocks but have no metadata to
  locate or interpret them. The pool is effectively lost.
- This is a **1% → 100% failure amplification**: 1% of your devices (the
  special device) becoming unavailable destroys 100% of your data.

### 1.2 Why operators are surprised

The "fast metadata tier" pattern is essential for cost-effective PB-scale
storage — a small amount of fast storage for metadata makes the pool feel fast
while bulk data lives on cheap HDDs. Operators naturally assume that metadata
device failure degrades performance (reads slow down when metadata must come
from HDDs). ZFS's implementation makes this assumption fatally wrong: metadata
device failure destroys the pool.

### 1.3 The tidefs guarantee

tidefs guarantees that **every metadata record exists in at least two device
classes** at all times. The metadata journal on fast devices is the *primary
read path*; the data journal on bulk devices is the *safety net*. If the
metadata journal devices fail:

1. Pool import succeeds (metadata is read from data journal)
2. All data is accessible (metadata is complete)
3. Reads are slower (HDD instead of NVMe) but correct
4. An alert fires: "metadata tier degraded, running in fallback mode"

---

## 2. Architecture

### 2.1 Dual-copy placement model

```
                         ┌─────────────────────────┐
  Metadata write ───────▶│  METADATA JOURNAL        │  NVMe tier (fast)
                         │  nvme0, nvme1            │  primary read path
                         │  (metadata_segment_size) │
                         └─────────────────────────┘
                                │
                                │ same write, second placement
                                ▼
                         ┌─────────────────────────┐
                         │  DATA JOURNAL            │  HDD tier (safe)
                         │  hdd0..hdd59             │  fallback read path
                         │  (data_segment_size)     │
                         └─────────────────────────┘
```

Every metadata write (inode, directory entry, extent map update, xattr, catalog
record) produces **two identical on-media records** placed in two different device
classes. The write is acknowledged only after both copies are durable.

### 2.2 What gets dual-copy treatment

| Record family | Dual-copy? | Rationale |
|---|---|---|
| InodeRecord (`type=2`) | Yes | Loss of inode = loss of file |
| DirEntryRecord (`type=3`) | Yes | Loss of dir entry = orphan inode |
| ExtentMapRecord (`type=4`) | Yes | Loss of extent map = inaccessible data |
| XattrRecord (`type=5`) | Yes | Loss of xattrs may break security |
| SnapshotCatalogRecord | Yes | Loss of snapshot catalog = lost snapshots |
| OrphanIndexRecord | Yes | Loss of orphan index = leaked space |
| SpaceDomainRecord | Yes | Loss of space domain = corrupted accounting |
| DatasetRecord | Yes | Loss of dataset root = unimportable dataset |
| PoolLabelV1 | Yes (special) | Pool label is written to all devices |
| **Data payload (extent bytes)** | **No** | Data lives only in data journal; metadata is the dual-copy surface |

The rule: **metadata gets dual-copy; data does not**. This keeps the write
amplification bounded: metadata is typically <1% of total pool IO, so the
dual-copy overhead is <1% of write bandwidth. Data redundancy is handled
separately by the shard/replica system (#1286).

### 2.3 Write path

```
  metadata record (e.g., InodeRecord)
         │
         ▼
  ┌──────────────────┐
  │  Encode + CRC32C  │
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │  Allocate segment │──→ metadata journal (fast tier)
  │  in metadata tier │
  └──────┬───────────┘
         │
         ├──→ append to metadata segment
         │
         ├──→ allocate segment in data journal (bulk tier)
         │
         ├──→ append to data segment (same bytes, same CRC)
         │
         ▼
  ┌──────────────────┐
  │  Ack after both   │
  │  copies durable   │
  └──────────────────┘
```

Both copies carry the **same binary record**, including the same CRC32C. A
reader cannot distinguish which tier produced the record — they are byte-for-byte
identical. The segment location (metadata journal vs. data journal) is the only
difference.

### 2.4 Read path (normal mode)

```
  metadata read (by record key)
         │
         ▼
  ┌──────────────────┐
  │  Lookup in        │
  │  metadata index   │──→ metadata journal segment (fast tier)
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │  Read + verify    │
  │  CRC32C           │
  └──────┬───────────┘
         │ success
         ▼
       return record
```

In normal mode, reads always hit the metadata journal (fast tier). The data
journal copy is present but not consulted — it only serves as a safety net.

### 2.5 Read path (degraded mode)

```
  metadata read (by record key)
         │
         ▼
  ┌──────────────────┐
  │  Lookup in        │
  │  metadata index   │──→ metadata journal UNAVAILABLE
  └──────┬───────────┘
         │ failure
         ▼
  ┌──────────────────┐
  │  Fallback lookup  │
  │  in data journal  │──→ data journal segment (bulk tier)
  │  index            │
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │  Read + verify    │
  │  CRC32C           │
  └──────┬───────────┘
         │ success
         ▼
       return record (slower but correct)
```

When the metadata journal is unavailable, reads fall back to the data journal.
The fallback is transparent to callers — they receive the same record bytes.
The only observable difference is increased latency.

---

## 3. Data Structures

### 3.1 MetadataRedundancyMode

```rust
/// Controls how metadata records are placed across device classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataRedundancyMode {
    /// Metadata is written only to the metadata journal (fast tier).
    /// This is the ZFS-like mode: fast, but metadata device loss = pool loss.
    /// Only allowed for test/dev pools, never for production.
    SingleCopy,

    /// Metadata is written to BOTH the metadata journal (fast tier) AND
    /// the data journal (bulk tier). This is the production default.
    /// Metadata device loss is survivable — reads fall back to data journal.
    DualCopy,

    /// Metadata is written to the metadata journal AND N data journal
    /// copies across distinct device classes. For extreme safety requirements.
    /// N is configured via `MetadataRedundancyConfig::extra_copies`.
    MultiCopy { extra_copies: u8 },
}

impl Default for MetadataRedundancyMode {
    fn default() -> Self {
        Self::DualCopy
    }
}
```

### 3.2 MetadataRedundancyConfig

```rust
/// Per-pool configuration for metadata redundancy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataRedundancyConfig {
    /// The redundancy mode for metadata records.
    pub mode: MetadataRedundancyMode,

    /// When true, pool import requires the metadata journal to be available.
    /// When false (default), pool import succeeds with only the data journal.
    /// Setting this to true restores ZFS-like behaviour (metadata device
    /// required), which is NOT recommended for production.
    pub require_metadata_journal_for_import: bool,

    /// When true, the pool automatically transitions to degraded mode when
    /// metadata journal devices become unavailable. When false, metadata
    /// journal unavailability causes pool suspension until devices return.
    pub auto_degrade: bool,

    /// Minimum number of metadata copies that must be readable to serve a
    /// metadata read. For DualCopy, this is always 1.
    pub min_readable_copies: u8,
}

impl Default for MetadataRedundancyConfig {
    fn default() -> Self {
        Self {
            mode: MetadataRedundancyMode::DualCopy,
            require_metadata_journal_for_import: false,
            auto_degrade: true,
            min_readable_copies: 1,
        }
    }
}
```

### 3.3 MetadataCopyLocation

```rust
/// Tracks where a specific metadata record copy resides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MetadataCopyLocation {
    /// Which device class holds this copy.
    pub device_class: DeviceClass,
    /// The device that holds this copy.
    pub device_id: u32,
    /// The segment within the device.
    pub segment_id: u64,
    /// Byte offset within the segment.
    pub segment_offset: u64,
}

/// Broad device class for metadata placement decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceClass {
    /// Fast tier: NVMe, Optane, or other low-latency devices.
    /// Used for the metadata journal region.
    MetadataTier,
    /// Bulk tier: HDDs or other high-capacity devices.
    /// Used for the data journal region.
    DataTier,
    /// Cache tier: FlashTier-like read cache devices.
    CacheTier,
}
```

### 3.4 MetadataIndex enhancement

The metadata index (which maps `(record_type, object_id) → segment_location`) is
extended to track **both** copies:

```rust
/// Entry in the metadata index. Tracks all known copies of a metadata record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataIndexEntry {
    /// The primary copy location (metadata journal, fast tier).
    /// None if the metadata journal is unavailable or this record predates
    /// dual-copy mode (legacy single-copy pools).
    pub primary: Option<MetadataCopyLocation>,

    /// The fallback copy location(s) (data journal, bulk tier).
    /// At least one fallback must exist for DualCopy and MultiCopy modes.
    pub fallbacks: Vec<MetadataCopyLocation>,

    /// COMMIT_GROUP at which this entry was last updated.
    pub commit_group: u64,
}
```

### 3.5 Pool-level metadata redundancy state

```rust
/// Runtime state tracking metadata redundancy health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataRedundancyState {
    /// Current operational mode.
    pub mode: MetadataRedundancyMode,

    /// Whether the pool is currently in degraded metadata mode.
    pub degraded: bool,

    /// When degraded mode began (monotonic timestamp).
    pub degraded_since: Option<u64>,

    /// Number of metadata reads that hit the fallback path since last reset.
    pub fallback_read_count: u64,

    /// Number of metadata journal devices currently available.
    pub metadata_devices_available: u32,

    /// Number of metadata journal devices configured.
    pub metadata_devices_configured: u32,

    /// Number of metadata records with only one copy (at-risk).
    /// Non-zero during initial dual-copy backfill or after partial device loss.
    pub at_risk_record_count: u64,
}
```

---

## 4. Algorithms

### 4.1 Dual-write protocol

```
dual_write(record_bytes: &[u8], record_key: RecordKey, commit_group: u64) -> Result<(), WriteError>

  1. Encode record with CRC32C → encoded_bytes

  2. Allocate segment in metadata journal (fast tier):
     loc_primary = metadata_allocator.allocate(encoded_bytes.len())

  3. Allocate segment in data journal (bulk tier):
     loc_fallback = data_allocator.allocate(encoded_bytes.len())

  4. Issue concurrent writes:
     fut_primary  = metadata_device.write(loc_primary, encoded_bytes)
     fut_fallback = data_device.write(loc_fallback, encoded_bytes)

  5. Await both writes:
     (res_primary, res_fallback) = join(fut_primary, fut_fallback)

  6. If either write fails:
     - Mark the failed device for health check
     - Retry on a different device of the same class (up to 3 retries)
     - If retries exhausted, return WriteError::DualWriteFailed

  7. Update metadata index with both locations:
     index.insert(record_key, MetadataIndexEntry {
         primary: Some(loc_primary),
         fallbacks: vec![loc_fallback],
         commit_group,
     })

  8. Return Ok(())
```

Key properties:
- **Concurrent writes**: primary and fallback writes are issued in parallel,
  not sequentially. Latency is `max(lat_primary, lat_fallback)`, not `lat_primary + lat_fallback`.
- **No fsync between copies**: both writes are in-flight simultaneously. The
  slowest device determines latency.
- **Atomic index update**: the metadata index is updated only after both writes
  succeed. A crash between writes leaves the old index entry intact (old copies
  remain valid) or produces an orphaned segment that GC will clean.

### 4.2 Degraded-mode read fallback

```
degraded_read(record_key: RecordKey) -> Result<Vec<u8>, ReadError>

  1. entry = metadata_index.get(record_key)

  2. Try primary copy:
     if let Some(loc) = &entry.primary:
         match read_from_location(loc):
             Ok(bytes) if crc_ok(bytes) => return Ok(bytes)
             _ => () // primary failed, continue to fallback

  3. Try fallback copies in order:
     for loc in &entry.fallbacks:
         match read_from_location(loc):
             Ok(bytes) if crc_ok(bytes) => {
                 increment fallback_read_count
                 return Ok(bytes)
             }
             _ => continue

  4. All copies failed:
     return Err(ReadError::AllCopiesUnreadable)

  5. If primary failed but fallback succeeded:
     - Log "metadata tier degraded read" (rate-limited)
     - Consider scheduling a repair write to restore the primary copy
       (background, not on the critical read path)
```

### 4.3 Pool import with metadata device loss

```
pool_import(device_paths: &[PathBuf], config: &ImportConfig) -> Result<Pool, ImportError>

  1. Probe all provided devices:
     for path in device_paths:
         metadata_devices, data_devices = classify_by_layout(path)

  2. Read pool label from any available device:
     pool_label = read_pool_label_from_any(metadata_devices ++ data_devices)

  3. Check metadata redundancy config:
     cfg = pool_label.metadata_redundancy

  4. If cfg.require_metadata_journal_for_import:
         if metadata_devices.is_empty():
             return Err(ImportError::MetadataJournalRequired)

  5. If metadata_devices.is_empty() and cfg.auto_degrade:
         // Enter degraded mode
         pool.degraded = true
         log_warn("metadata tier unavailable, pool operating in fallback mode")
         log_warn("metadata reads will use data journal — performance degraded")

  6. Open available devices:
     for device in (metadata_devices ++ data_devices):
         open_device(device)

  7. Rebuild metadata index:
     // In degraded mode, scan data journal for metadata records
     if metadata_devices.is_empty():
         index = rebuild_index_from_data_journal(data_devices)
     else:
         index = rebuild_index_from_both(metadata_devices, data_devices)

  8. Return Pool { degraded, index, ... }
```

### 4.4 Metadata journal device replacement

```
replace_metadata_device(old_device: DevicePath, new_device: DevicePath) -> Result<(), ReplaceError>

  1. Verify new device is suitable (size, class, health)

  2. Add new device to metadata journal device set:
     pool.add_metadata_device(new_device)

  3. Backfill metadata from data journal to new metadata device:
     for (record_key, entry) in index.iter():
         if entry.primary.is_none() or entry.primary.device == old_device:
             // Read fallback copy from data journal
             bytes = read_from_location(entry.fallbacks[0])
             // Write to new metadata device
             new_loc = write_to_device(new_device, bytes)
             // Update index
             entry.primary = Some(new_loc)

  4. Once backfill completes:
     pool.remove_metadata_device(old_device)
     // Pool now has a healthy metadata tier again

  5. Exit degraded mode (if applicable)
```

### 4.5 Adding metadata tier to an existing pool

```
add_metadata_tier(pool: &Pool, devices: &[DevicePath]) -> Result<(), AddTierError>

  1. Verify devices are suitable for metadata tier

  2. For each device:
     pool.add_metadata_device(device)
     // Device is initialized with a metadata journal region

  3. Backfill existing metadata to new metadata devices:
     for (record_key, entry) in index.iter():
         // Read from data journal (current only copy)
         bytes = read_from_location(entry.fallbacks[0])
         // Write to new metadata device
         new_loc = write_to_device(device, bytes)
         // Update index
         entry.primary = Some(new_loc)

  4. Update pool metadata redundancy state

  5. Pool now has fast metadata reads via the new tier
```

This is a key operational advantage over ZFS: ZFS cannot add a special device to
an existing pool without a full send/recv. tidefs can add a metadata tier to
any pool at any time — the backfill is a background process that copies metadata
from the data journal to the new fast devices.

---

## 5. Integration with Existing Designs

### 5.1 Device Layout Policies (#1193)

The `DeviceLayoutV1` record already defines separate metadata and data journal
regions per device. This design adds the concept of **device class** at the pool
level:

```rust
// Extension to DeviceLayoutV1
pub struct DeviceLayoutV1 {
    // ... existing fields ...

    /// Device class for metadata placement decisions.
    /// MetadataTier devices hold the metadata journal as the primary copy.
    /// DataTier devices hold the data journal as the fallback copy.
    pub device_class: DeviceClass,
}
```

During pool creation, the operator assigns each device to a class:

```
PoolMeta:
  devices:
    - path: /dev/nvme0n1
      class: MetadataTier
    - path: /dev/nvme1n1
      class: MetadataTier
    - path: /dev/sda
      class: DataTier
    - path: /dev/sdb
      class: DataTier
    ...
```

A device can belong to only one class. The device class determines which journal
regions are active on that device:

| Device class | Active regions |
|---|---|
| `MetadataTier` | System Area, Metadata Journal |
| `DataTier` | System Area, Poolmap Journal, Data Journal |

Note: `MetadataTier` devices do NOT have a data journal region. `DataTier`
devices DO have a metadata journal region — but it is used only for the
fallback copy, not the primary read path. This means a `DataTier` device's
metadata journal region is smaller than a `MetadataTier` device's (enough for
the dual-copy safety net, not the full working set).

### 5.2 Extent Management (#1191)

The `extent_id` indirection model makes dual-copy natural. Metadata records
(inodes, extent maps, directory entries) reference extents by `extent_id`.
Extent data (the actual file bytes) lives only in the data journal — it is not
dual-copied. Only the metadata *about* extents (ExtentMapRecord) gets dual-copy
treatment.

```
  InodeRecord (dual-copy) ──→ ExtentMapRecord (dual-copy) ──→ [extent_id_1, extent_id_2, ...]
                                                                      │
                                                                      ▼
                                                              Data payload (single-copy,
                                                              in data journal only)
```

If extent data needs redundancy, that is handled by the shard/replica system
(#1286), not by metadata dual-copy.

### 5.3 COMMIT_GROUP State Machine (#1267)

Metadata dual-copy integrates with the commit_group commit pipeline:

```
  COMMIT_GROUP OPEN → accumulate metadata writes (dual-copy in memory)
           → COMMIT_GROUP QUIESCE → stop accepting new writes
           → COMMIT_GROUP SYNC → flush all dual-copy writes to both tiers
           → COMMIT_GROUP COMMIT → update metadata index atomically
```

During COMMIT_GROUP SYNC, the metadata journal and data journal writes for a given COMMIT_GROUP
are flushed together. The COMMIT_GROUP is not committed until both tiers acknowledge the
writes. If one tier fails during SYNC, the COMMIT_GROUP can still commit with the other
tier, and the pool transitions to degraded mode.

### 5.4 Intent Log / LOG_DEVICE (#1252)

The intent log is a fast path for synchronous writes. Metadata records written
via the intent log also get dual-copy treatment:

```
  fsync → intent log append (fast tier, NVMe)
        → intent log fold into COMMIT_GROUP
        → COMMIT_GROUP SYNC writes metadata to both tiers
```

The intent log itself may be on a separate log device. The log device is not
the metadata journal — it is a write-ahead log for sync operations. The
dual-copy guarantee applies to the metadata records after they are folded from
the intent log into the commit_group commit.

### 5.5 On-Media Format (#1220)

No new record types are needed. The dual-copy mechanism operates at the
segment/journal level, not the record level. The same `InodeRecord`,
`DirEntryRecord`, `ExtentMapRecord`, etc. are written to both tiers. No format
changes are required.

One TLV extension is added to `DatasetRecord`:

| TLV Type | Name | Description |
|---|---|---|
| `0x0100` | `TLV_METADATA_REDUNDANCY_CONFIG` | Serialized `MetadataRedundancyConfig` |

This TLV is written to the `DatasetRecord` at pool creation and read during
pool import. It is how the pool remembers its metadata redundancy policy
across mounts.

### 5.6 Shard Groups and Rebake (#1286)

Metadata dual-copy and data shard redundancy are orthogonal:

| Concern | Metadata dual-copy (#1281) | Data shard redundancy (#1286) |
|---|---|---|
| What is protected | Metadata records (inodes, dirs, extent maps) | Data payload (extent bytes) |
| Redundancy mechanism | Write two copies to two device classes | Erasure-code data into k+m shards |
| Latency model | Dual write at ingest time | Write 1x at ingest, rebake to k+m in background |
| Failure mode | Metadata tier loss → fallback reads | Shard loss → reconstruct from remaining shards |
| Write amplification | 2x for metadata (<1% of IO) | 1x at ingest; k+m after rebake |

They are complementary: metadata dual-copy ensures the pool is always
importable and navigable; data shard redundancy ensures file contents survive
device failures.

---

## 6. Operational States and Transitions

### 6.1 State machine

```
                    ┌──────────┐
                    │  NORMAL  │  metadata journal healthy
                    └────┬─────┘
                         │
          metadata journal│  metadata journal
          device added    │  device lost/failed
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
   ┌────────────┐               ┌──────────────┐
   │ BACKFILLING│               │  DEGRADED    │
   │ (optional) │               │  fallback     │
   └─────┬──────┘               │  reads active │
         │                      └──────┬───────┘
         │ backfill complete           │
         │                      metadata journal
         │                      device restored
         │                             │
         └──────────┬──────────────────┘
                    ▼
              ┌──────────┐
              │  NORMAL  │
              └──────────┘
```

| State | Description | Read path | Write path |
|---|---|---|---|
| **NORMAL** | Metadata journal healthy, dual-copy intact | Fast tier (metadata journal) | Dual-copy (both tiers) |
| **DEGRADED** | Metadata journal unavailable, pool survived | Fallback (data journal) | Single-copy (data journal only, queued for backfill) |
| **BACKFILLING** | Metadata journal restored, copying metadata from data journal | Fast tier where backfill complete, fallback elsewhere | Dual-copy (resumed) |

### 6.2 Transition triggers

| Transition | Trigger | Automatic? |
|---|---|---|
| NORMAL → DEGRADED | All metadata journal devices fail health check | Yes (if `auto_degrade: true`) |
| DEGRADED → NORMAL | Metadata journal devices return + backfill complete | Manual (operator confirms health before promotion) |
| NORMAL → BACKFILLING | Operator adds new metadata journal devices | Triggered by `add_metadata_device` |
| BACKFILLING → NORMAL | All metadata records have primary copies | Automatic (backfill completes) |

### 6.3 Degraded mode semantics

In degraded mode:

- **Reads**: slower (HDD instead of NVMe) but correct. All metadata is readable
  from the data journal.
- **Writes**: metadata is written only to the data journal (single copy).
  The pool tracks which records were written during degraded mode and
  backfills them to the metadata journal when it returns.
- **Pool import**: succeeds without metadata journal devices.
- **Alert**: "metadata tier degraded, running in fallback mode since <timestamp>.
   Metadata read latency increased. Replace metadata devices to restore
   performance."
- **Monitoring**: `fallback_read_count` and `at_risk_record_count` are exported
  via the observability surface (#1270).

---

## 7. Space Accounting

### 7.1 Write amplification

Metadata is typically <1% of total pool IO (measured across ZFS deployments at
scale). The dual-copy model therefore adds <1% write amplification to the pool.
This is acceptable for the safety guarantee.

| Pool size | Metadata size (est. 0.5%) | Dual-copy overhead | Acceptable? |
|---|---|---|---|
| 10 TiB | 50 GiB | 50 GiB (0.5%) | Yes |
| 100 TiB | 500 GiB | 500 GiB (0.5%) | Yes |
| 1 PiB | 5 TiB | 5 TiB (0.5%) | Yes |
| 10 PiB | 50 TiB | 50 TiB (0.5%) | Yes |

### 7.2 Metadata journal sizing with dual-copy

Data-tier devices need a metadata journal region large enough to hold the
fallback copies. The data-tier metadata journal is sized proportionally:

```
data_tier_metadata_journal_size = metadata_tier_metadata_journal_size / replication_factor
```

Where `replication_factor` accounts for the fact that data-tier devices
collectively hold one copy of metadata, distributed across all data devices.
For a pool with 2 metadata devices and 60 data devices:

```
metadata_tier_journal = 256 × data_segment_size (e.g., 256 × 32 MiB = 8 GiB)
data_tier_metadata_per_device = metadata_tier_journal / 60 ≈ 136 MiB
```

This is small enough to fit within the existing metadata journal region
allocation (which is already 256 × data_segment_size on data-tier devices per
#1193 §5.1). On data-tier devices, the metadata journal region serves double
duty: it holds pool-local metadata AND fallback copies for dual-copy.

### 7.3 GC interaction

Both copies of a metadata record must be freed when the record is deleted
(e.g., file deletion, directory removal, snapshot destruction). The metadata
cleaner must:

1. Mark the primary copy (metadata journal) as dead
2. Mark the fallback copy (data journal) as dead
3. Both segment stores independently reclaim the space

This is handled by the existing segment cleaner — it already operates
per-region and per-segment. Each copy lives in a different region, so each
region's cleaner handles its own dead records.

---

## 8. Error Handling

### 8.1 Write errors

| Scenario | Handling |
|---|---|
| Primary write succeeds, fallback fails | Primary write is still valid. Retry fallback on a different data device (up to 3x). If all retries fail, record is at-risk (single copy). Pool logs "metadata redundancy degraded for record <key>". |
| Primary write fails, fallback succeeds | Retry primary on a different metadata device. If all retries fail, the pool may transition to degraded mode if this is the last metadata device. |
| Both writes fail | Return `WriteError::DualWriteFailed`. Caller handles (typically commit_group abort or filesystem error). |

### 8.2 Read errors

| Scenario | Handling |
|---|---|
| Primary CRC mismatch, fallback OK | Return fallback bytes. Schedule background repair of primary copy. |
| Primary OK, fallback CRC mismatch | Return primary bytes. Schedule background repair of fallback copy. |
| Both copies CRC mismatch | Return `ReadError::AllCopiesCorrupt`. Trigger pool repair (scrub). |
| Primary device unavailable, fallback OK | Return fallback bytes. Increment degraded read counter. Pool in degraded mode. |
| Both devices unavailable | Return `ReadError::NoCopiesAvailable`. Pool is effectively dead (all device classes lost). |

### 8.3 Pool import errors

| Scenario | Handling |
|---|---|
| Metadata journal devices missing, `require_metadata_journal_for_import: false` | Succeed. Enter degraded mode. Log warning. |
| Metadata journal devices missing, `require_metadata_journal_for_import: true` | Fail with `ImportError::MetadataJournalRequired`. Operator must restore metadata devices or override config. |
| Data journal devices all missing | Fail with `ImportError::NoDataDevices`. Pool is dead (data journal is required). |
| Pool label corrupted on all devices | Fail with `ImportError::NoValidPoolLabel`. Pool is dead. |

---

## 9. Implementation Plan

### Phase 1: Types and Configuration (issue #1281-impl-1)

- Define `MetadataRedundancyMode`, `MetadataRedundancyConfig`, `MetadataCopyLocation`,
  `DeviceClass` in `crates/tidefs-types-dataset-lifecycle-core/`
- Define `MetadataRedundancyState` for runtime tracking
- Add `TLV_METADATA_REDUNDANCY_CONFIG` to the TLV registry in
  `tidefs-binary_schema-core`
- Add `MetadataRedundancyConfig` serialization to `DatasetRecord` TLV area
- No on-media format changes needed (config lives in existing TLV area)

### Phase 2: Device Class Assignment (issue #1281-impl-2)

- Extend `DeviceLayoutV1` with `device_class: DeviceClass` field
- Extend pool creation CLI/config to accept per-device class assignments
  must exist (dual-copy requires both tiers)

### Phase 3: Dual-Write Path (issue #1281-impl-3)

- Implement `dual_write()` as specified in §4.1
- Modify metadata write path in `tidefs-local-filesystem` to use dual-write
  when `mode == DualCopy`
- Concurrent write issuance using `tokio::join!` or equivalent
- Index update after both writes succeed
- Write error handling with retry (per §8.1)

### Phase 4: Degraded-Mode Read Fallback (issue #1281-impl-4)

- Extend `MetadataIndexEntry` with fallback locations
- Implement `degraded_read()` as specified in §4.2
- CRC32C verification on both primary and fallback reads
- Background repair scheduling for CRC mismatches

### Phase 5: Pool Import Resilience (issue #1281-impl-5)

- Implement pool import with metadata device loss tolerance (§4.3)
- Rebuild metadata index from data journal when metadata devices unavailable
- Enter degraded mode automatically when `auto_degrade: true`
- Log prominent warning on degraded import

### Phase 6: Operational Tooling (issue #1281-impl-6)

- Implement `tidefs pool metadata-tier add <devices>` command
- Implement `tidefs pool metadata-tier remove <device>` command
- Implement `tidefs pool metadata-tier replace <old> <new>` command
- Backfill logic for adding metadata tier to existing pools
- Backfill logic for replacing metadata devices

### Phase 7: Monitoring and Observability (issue #1281-impl-7)

- Export `MetadataRedundancyState` via observability surface (#1270)
- Export `fallback_read_count` as a Prometheus counter
- Export `degraded` as a Prometheus gauge
- Export `at_risk_record_count` as a Prometheus gauge
- Alert rule: `degraded == 1` → page operator
- Alert rule: `at_risk_record_count > 0` → warn operator


- Unit tests for dual-write success, partial failure, total failure
- Unit tests for degraded read fallback (all paths in §8.2)
- Unit tests for pool import with/without metadata devices
- Integration test: create pool → write metadata → kill metadata devices →
  import pool → read all metadata → verify correctness
- Integration test: add metadata tier to existing pool → verify backfill
- Chaos test: random metadata device failures during sustained write load
- xtask gate: `tidefs-xtask check-metadata-redundancy`

---

## 10. Tradeoffs and Design Decisions

### 10.1 Why dual-copy at write time rather than background sync?

**Decision**: Write both copies synchronously at ingest time.

**Alternatives considered**:
- **Background sync**: Write to metadata journal first, asynchronously copy
  to data journal later. Rejected because a crash between write and sync
  leaves metadata only on the metadata tier — the exact ZFS vulnerability
  we are trying to avoid.
- **Intent-log-based sync**: Log the metadata write to an intent log, then
  lazily apply to both tiers. Rejected because it adds complexity without
  reducing the synchronous cost (the intent log itself must be durable).

**Rationale**: Synchronous dual-write is the only way to guarantee that
metadata is always in two device classes. The latency cost is bounded:
metadata writes are small (typically <1 KB) and concurrent writes to both
tiers overlap. The data tier write is slow but non-blocking because it
runs in parallel with the fast-tier write.

### 10.2 Why not three copies?

**Decision**: Two copies (one per device class) is the production default.
Three or more copies (`MultiCopy`) is available as an option.

**Rationale**: Two copies in two device classes provides the essential
guarantee: no single device class failure can destroy the pool. Three copies
would protect against simultaneous failure of two device classes — a scenario
so unlikely (NVMe tier AND HDD tier failing simultaneously) that the extra
write amplification is not justified as a default.

### 10.3 Why not erasure-code metadata?

**Decision**: Metadata uses full-copy redundancy, not erasure coding.

**Rationale**: Metadata records are small (typically 128-512 bytes) and
numerous. Erasure coding small records produces high overhead (k+m shards
for a 256-byte record is wasteful). Full copies are simpler, cheaper, and
correct for this use case. Erasure coding is reserved for data payloads
(#1286) where records are large (MB-scale extents).

### 10.4 Why device class assignment is at pool creation?

**Decision**: Device class is a pool-level assignment, not per-dataset.

**Rationale**: The metadata redundancy guarantee is a pool-level property.
All datasets in the pool share the same metadata journal devices. Per-dataset
metadata tiering would require per-dataset metadata journals, which adds
significant complexity (separate segment stores, allocators, and indexes
per dataset). The pool-level model is simpler and matches operational
practice: operators provision fast storage at the pool level.

### 10.5 SingleCopy mode for testing

`SingleCopy` mode (metadata only on fast tier) is provided for test/dev
environments where device loss is acceptable. It must NOT be the default
and must be explicitly enabled with a `--allow-single-copy-metadata` flag.
Production pools created with `SingleCopy` mode log a warning at every
mount: "metadata is not redundant — metadata device loss will destroy
this pool".

---

## 11. ZFS Comparison Summary

| Dimension | ZFS | tidefs |
|---|---|---|
| Metadata placement | Exclusive to special device | Dual-copy: metadata journal + data journal |
| Special device failure | Pool destroyed | Pool degraded (slower reads, data intact) |
| Pool import after metadata loss | Impossible | Succeeds (reads metadata from data journal) |
| Add metadata tier to existing pool | Not possible (requires send/recv) | Yes (background backfill) |
| Replace metadata devices online | Risky (pool lost if replacement fails) | Safe (data journal is always the fallback) |
| Metadata write amplification | 1x | 2x for metadata (<1% of pool IO) |
| Latency impact | Fast NVMe writes only | `max(NVMe_lat, HDD_lat)` ≈ HDD latency for writes. Read latency unaffected in normal mode. |

---

## 12. Open Questions

1. **Should metadata journal devices have a dedicated data journal region
   for dual-copy?** Currently, `MetadataTier` devices only have a metadata
   journal region. The fallback copy goes to `DataTier` devices. This means
   `MetadataTier` devices cannot serve as fallback for each other. Should
   `MetadataTier` devices also have a small data journal region for
   cross-metadata-device fallback? Decision deferred to implementation
   based on operator feedback.

2. **Should the dual-copy guarantee extend to the pool label?** The pool
   label is already written to every device (per #1254). However, if all
   metadata devices are lost AND the pool label on data devices is corrupted,
   the pool is unimportable. Consider a pool-label-specific redundancy
   scheme (e.g., erasure-coded pool label across data devices). Defer to
   #1254 hardening.

3. **Backfill prioritization**: When a metadata tier is added to an existing
   pool, the backfill may need to copy TB-scale metadata. Should backfill
   be prioritized over user IO? Proposed: backfill runs at
   `Priority::Low` in the background scheduler, with a configurable
   bandwidth cap. Hot metadata (recently accessed) is backfilled first.

4. **Partial metadata journal loss**: If 2 of 4 metadata devices fail,
   the remaining 2 still serve reads. But the pool may have incomplete
   metadata (records written to the failed devices before dual-copy was
   acknowledged). How do we detect and repair this? Proposed: a
   `metadata_scrub` that cross-references metadata index entries against
   actual on-media records, triggered after device loss.

---

## 13. References

- [#1193] Device layout policies and adaptive segment sizing
- [#1220] On-media record format strategy — V1 unified design
- [#1254] Pool import/export and online device topology management
- [#1267] Canonical commit ordering and commit_group state machine
- [#1191] Extent management architecture
- [#1252] Intent log and separate log device (LOG_DEVICE)
- [#1256] Cache device tiering and second-level read cache
- [#1286] Shard groups, replicas, and rebake pathway
- [#1270] Observability surface (prometheus metrics)
- [#1238] Unified on-media format lifecycle
- `docs/ZFS_CEPH_DESIGN_MISTAKE_COVERAGE_MATRIX.md` — mistake #30
- ZFS special device documentation: `zpoolconcepts(7)` — "Special Allocation Class"
