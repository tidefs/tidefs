# Pool Import/Export — 7-Phase Implementation Plan

**Issue**: [#1971](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1971)
**Canonical design**: [`docs/design/pool-import-export-device-topology-management.md`](pool-import-export-device-topology-management.md) (sealed via #1944)
**Status**: design-spec
**Maturity**: design-spec — this document extends the sealed canonical design with per-phase data structures, algorithms, tradeoffs, and per-metaslab parallelism deferral rationale.
**Lane**: storage-core
**Kind**: design
**Hard-gate**: yes
**Crate targets**: `tidefs-local-object-store` (Pool, Device, ClassMap, PoolImporter, PoolExporter, DeviceManager), `tidefs-types-pool-label-core` (PoolLabelV1 — already implemented), `tidefs-pool-allocator` (per-metaslab cursors — Phase 6 already done)

---

## 0. Relationship to canonical design

This document is a **companion specification** to the sealed canonical design at
[`pool-import-export-device-topology-management.md`](pool-import-export-device-topology-management.md).
The canonical design defines the PoolLabelV1 on-device format, pool import/export
protocols, device topology management, failure handling, hot-spare policy, and
cluster-aware ownership model. This document expands on **Section 16
(Implementation Plan)** of the canonical design with:

- Per-phase data structures and their Rust type layouts,
- Algorithm pseudocode for each phase's critical path,
- Tradeoff analysis for design decisions within each phase,
- Explicit deferral rationale for per-metaslab parallelism,
- Integration contracts between phases and adjacent subsystems.

**Reading order**: Start with the canonical design for the big picture, then
use this document for implementation-level detail.

---

## 1. Architecture overview (implementation view)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Implementation Crate Map                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  tidefs-types-pool-label-core (Phase 1 — DONE)                       │
│  ├─ PoolLabelV1, PoolState, DeviceClass                               │
│  ├─ seal_label / encode_label / decode_label / verify_label_checksum │
│  └─ POOL_LABEL_SIZE = 256 KiB, POOL_NAME_MAX = 255                   │
│                                                                      │
│  tidefs-local-object-store (Phases 2–6 target)                       │
│  ├─ pool.rs: Pool, PoolConfig, PoolHealth, PoolProperties, FailMode  │
│  ├─ device.rs: Device, DeviceKind, DeviceState, DeviceImpl, DeviceClass,       │
│  │            IoClass, DeviceStats, DeviceStatus                          │
│  ├─ pool_importer.rs (new): PoolImporter, CandidatePool, ScanResult  │
│  ├─ pool_exporter.rs (new): PoolExporter, ExportStatus                │
│  ├─ device_manager.rs (new): DeviceManager, DeviceOp, SparePolicy    │
│  └─ evacuation.rs (new, Phase 5): EvacuationCursor, EvacProgress      │
│                                                                      │
│  tidefs-pool-allocator (Phase-adjacent — DONE)                       │
│  ├─ PoolAllocator, SegmentFreeMap, MetaslabAllocStats                 │
│  ├─ Per-metaslab cursors (ready for parallelism, not yet parallel)    │
│  └─ Pressure signaling, ENOSPC propagation                            │
│                                                                      │
│  tidefs-xtask (Phase 7 target)                                        │
│  └─ check-pool-import-export, check-device-topology,                  │
│      check-label-corruption                                           │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data structures (per-phase detail)

### 2.1 Phase 1: PoolLabelV1 (DONE)

Already implemented in `tidefs-types-pool-label-core`. Key types:

```rust
// tidefs-types-pool-label-core/src/lib.rs (implemented)
pub const POOL_LABEL_MAGIC: [u8; 4] = *b"VBFS";
pub const POOL_LABEL_SIZE: usize = 256 * 1024;
pub const POOL_NAME_MAX: usize = 255;

#[repr(u8)]
pub enum PoolState { Active = 0, Exported = 1, Destroyed = 2 }

#[repr(u8)]
pub enum DeviceClass { Hdd = 0, Ssd = 1, Nvme = 2, LogDevice = 3, Cache = 4, Special = 5 }

pub struct PoolLabelV1 {
    pub magic: [u8; 4],
    pub version: u32,
    pub pool_guid: [u8; 16],
    pub device_guid: [u8; 16],
    pub pool_name_len: u16,
    pub pool_name: [u8; POOL_NAME_MAX],
    pub pool_state: PoolState,
    pub commit_group: u64,
    pub label_commit_group: u64,
    pub device_index: u32,
    pub topology_generation: u64,
    pub device_count: u32,
    pub device_class: DeviceClass,
    pub device_capacity_bytes: u64,
    pub system_area_pointer: u64,
    pub system_area_size: u64,
    pub features_incompat: u64,
    pub features_ro_compat: u64,
    pub features_compat: u64,
    pub checksum: [u8; 32],
}

pub fn seal_label(label: PoolLabelV1) -> Result<PoolLabelV1, LabelError>;
pub fn encode_label(label: &PoolLabelV1, buf: &mut [u8]) -> Result<(), LabelError>;
pub fn decode_label(buf: &[u8]) -> Result<PoolLabelV1, LabelError>;
pub fn verify_label_checksum(label: &PoolLabelV1) -> bool;
```

**Tradeoff: fixed-size pool name vs variable-length encoding**. A fixed 255-byte
`pool_name` field wastes ~250 bytes per label for typical short names, but
eliminates a length-prefixed dynamic encoding that would complicate checksum
boundaries and make label parsing fragile. The 256 KiB label size makes this
waste negligible (<0.1%).

**Tradeoff: BLAKE3 vs BLAKE2 vs SHA-256**. BLAKE3 is ~3× faster than SHA-256 on
x86_64 with SIMD, and its tree-hashing construction allows incremental label
updates if needed later. The 256-bit output is collision-resistant and fits
naturally in a `[u8; 32]` field. BLAKE2 would work but BLAKE3 is the modern
choice already used in the TideFS content-addressable store.

### 2.2 Phase 2: PoolImporter (NOT YET IMPLEMENTED)

```rust
// Proposed: crates/tidefs-local-object-store/src/pool_importer.rs

/// Result of scanning a single candidate device.
pub struct DeviceCandidate {
    pub path: PathBuf,
    pub label: PoolLabelV1,
    pub label_location: LabelLocation,  // L0 (offset 0) or L1 (end of device)
    pub label_valid: bool,
}

pub enum LabelLocation { L0, L1 }

/// A group of devices sharing the same pool_guid.
pub struct CandidatePool {
    pub pool_guid: [u8; 16],
    pub pool_name: String,
    pub devices: Vec<DeviceCandidate>,
    pub topology_generation: u64,       // majority vote
    pub max_commit_group: u64,                   // recovery commit_group
    pub is_importable: bool,
}

pub enum ImportError {
    MissingDevice { device_index: u32 },
    SplitTopology { generations: Vec<u64> },
    LabelChecksumMismatch { device: PathBuf },
    BadMagic { device: PathBuf },
    UnsupportedVersion { device: PathBuf, version: u32 },
    DestroyedPool,
}

/// Entry point for pool import.
pub struct PoolImporter {
    /// Paths or glob patterns to scan for device labels.
    pub search_paths: Vec<PathBuf>,
}

impl PoolImporter {
    /// Scan candidate devices in search_paths, read labels, return raw candidates.
    pub fn scan_candidates(&self) -> Result<Vec<DeviceCandidate>, ImportError>;

    /// Group candidates by pool_guid into CandidatePools.
    pub fn group_by_pool_guid(
        candidates: Vec<DeviceCandidate>,
    ) -> Vec<CandidatePool>;

    /// majority vote, checksums, importability.

    /// rebuild ClassMap, open devices.
    pub fn import_pool(&self, pool: CandidatePool) -> Result<Pool, ImportError>;
}
```

#### 2.2.1 Scan algorithm

```
function scan_candidates(search_paths):
    candidates = []
    for each path in search_paths:
        for each device in resolve_path(path):  // expand globs, follow symlinks
            if not is_block_device(device):
                continue
            size = get_device_size(device)
            l0_label = read_label(device, offset=0)
            l1_label = read_label(device, offset=size - POOL_LABEL_SIZE)
            best = resolve_labels(l0_label, l1_label)  // prefer higher label_commit_group
            if best is not None:
                candidates.push(DeviceCandidate {
                    path: device,
                    label: best.label,
                    label_location: best.location,
                    label_valid: true,
                })
    return candidates

function resolve_labels(l0, l1):
    // Prefer the copy with the higher label_commit_group.
    // If one checksum fails, use the other.
    // If both fail, device is not a pool member.
    l0_ok = l0.is_some() and verify_checksum(l0)
    l1_ok = l1.is_some() and verify_checksum(l1)
    if not l0_ok and not l1_ok: return None
    if l0_ok and not l1_ok: return {label: l0, location: L0}
    if l1_ok and not l0_ok: return {label: l1, location: L1}
    if l0.label_commit_group >= l1.label_commit_group: return {label: l0, location: L0}
    return {label: l1, location: L1}
```

**Tradeoff: scan vs config-file import**. ZFS supports `zpool import -d /dev/disk/by-id`
(directory scan) and `zpool import -c cachefile` (pre-cached config). TideFS
starts with directory scan only. A config-file cache is a performance
optimization, not a correctness requirement — the labels are the source of
truth. Config-file caching is deferred to a continuation wire-up issue.

**Tradeoff: majority vote vs strict consistency for topology_generation**.
During a partial label write (crash mid-commit_group), different devices may show
different `topology_generation` values. A strict consistency check would
refuse import. The majority-vote rule allows import when a quorum of devices
agree, which is the common case. A `force_import` flag bypasses the majority
check for disaster recovery.

### 2.3 Phase 3: PoolExporter (NOT YET IMPLEMENTED)

```rust
// Proposed: crates/tidefs-local-object-store/src/pool_exporter.rs

pub struct PoolExporter {
    pub pool: Pool,
}

pub enum ExportStatus {
    /// Export completed; all labels set to EXPORTED.
    Exported,
    /// Export failed; pool may be in split state. Re-run export or force-import.
    Failed(String),
}

pub enum ExportPhase {
    Quiesce,   // Stop new writes, drain inflight commit_groups
    Flush,     // Flush all pending commit_groups to stable storage
    Sync,      // Fsync all devices
    WriteLabels, // Atomic label write (all ACTIVE → EXPORTED)
    Verify,    // Re-read labels to confirm
}

impl PoolExporter {
    /// Export the pool: quiesce, flush, sync, write EXPORTED labels, verify.
    /// Returns ExportStatus::Exported on success.
    pub fn export_pool(&mut self) -> Result<ExportStatus, ExportError>;

    /// Per-phase progress for observability.
    pub fn export_phase(&self) -> ExportPhase;

    /// Force-export even if some devices are DEGRADED/FAULTED.
    /// Writes EXPORTED to all reachable devices; missing devices remain ACTIVE.
    pub fn force_export(&mut self) -> Result<ExportStatus, ExportError>;
}
```

#### 2.3.1 Export algorithm (three-phase protocol)

```
function export_pool(pool):
    // Phase 1: Quiesce — stop new writes
    quiesce_all_datasets(pool)          // gate new commit_group formation
    wait_for_inflight_commit_groups(pool)        // drain committed-but-not-flushed commit_groups

    // Phase 2: Flush + Sync
    flush_all_devices(pool)               // write all dirty data
    sync_all_devices(pool)                // fsync/fdatasync every device
    write_system_area_checkpoint(pool)  // atomic checkpoint marker

    // Phase 3: Write EXPORTED labels (all-or-nothing)
    labels = []
    for each device in pool.devices:
        label = read_current_label(device)
        label.pool_state = EXPORTED
        label.label_commit_group += 1
        label = seal_label(label)
        labels.push((device, label))

    // Write L0 and L1 for each device
    for (device, label) in labels:
        write_label(device, offset=0, label)           // L0
        write_label(device, offset=device.size - 256K, label)  // L1

    // Verify
    for (device, _) in labels:
        l0 = read_label(device, 0)
        l1 = read_label(device, device.size - 256K)
        if l0.pool_state != EXPORTED or l1.pool_state != EXPORTED:
            return ExportStatus::Failed("label verification mismatch")

    return ExportStatus::Exported
```

**Tradeoff: offline-only export vs online export**. ZFS requires unmounting all
datasets before `zpool export`. This design follows the same model: quiesce
guarantees no in-flight writes, making the export atomic. Online export
(export while serving I/O) would require a distributed barrier across all
writers and is substantially more complex. TideFS defers online export to a
future design iteration.

**Tradeoff: two-label write vs single-label write**. Writing both L0 and L1
doubles the I/O but provides crash resilience: if the system crashes after
writing L0 but before L1, the import protocol resolves the split state by
preferring the higher `label_commit_group`. A single-label write would be faster but
leaves no redundancy for the label itself.

### 2.4 Phase 4: Online device addition (NOT YET IMPLEMENTED)

```rust
// Proposed: crates/tidefs-local-object-store/src/device_manager.rs

pub struct DeviceManager {
    pub pool: Pool,
}

pub struct DeviceAddRequest {
    pub path: PathBuf,
    pub device_class: DeviceClass,
    pub ashift: u8,
}

pub enum DeviceOpStatus {
    Committed,
    Failed(String),
}

impl DeviceManager {
    /// Add a device to an online pool.
    /// Returns after the topology change is committed to all labels.
    pub fn add_device(&mut self, req: DeviceAddRequest) -> Result<DeviceOpStatus, DeviceError>;

    /// Remove a device from an online pool (Phase 5 — requires evacuation first).
    pub fn remove_device(&mut self, device_index: u32) -> Result<DeviceOpStatus, DeviceError>;

    /// Replace a device: add new, rebuild, remove old (Phase 6).
    pub fn replace_device(
        &mut self,
        old_device_index: u32,
        new_device: DeviceAddRequest,
    ) -> Result<DeviceOpStatus, DeviceError>;
}
```

#### 2.4.1 Add device algorithm (commit_group-consistent batch update)

```
function add_device(pool, req):
    // 1. Precondition checks
    assert(pool.state == ACTIVE)
    assert(device_not_already_in_pool(pool, req.path))

    // 2. Label the new device
    new_label = PoolLabelV1::new(...)
    new_label.device_index = pool.devices.len()
    new_label.topology_generation = pool.topology_generation + 1
    new_label.device_count = pool.devices.len() + 1
    new_label = seal_label(new_label)
    write_label(req.path, offset=0, new_label)       // L0
    write_label(req.path, offset=size-256K, new_label) // L1

    // 3. Open a new commit_group for the topology change
    commit_group = pool.commit_group_state.open_commit_group()

    // 4. Update all existing device labels in the same commit_group
    for each device in pool.devices:
        label = read_current_label(device)
        label.topology_generation += 1
        label.device_count += 1
        label.label_commit_group = commit_group
        label = seal_label(label)
        write_label(device, 0, label)
        write_label(device, size-256K, label)

    // 5. Rebuild ClassMap with the new device
    pool.class_map.add_device(new_device, req.device_class)

    // 6. Open and initialize the new device
    device = Device::open(req.path, new_label)
    device.initialize_system_area()
    pool.devices.push(device)

    // 7. Commit the commit_group — makes topology change durable
    pool.commit_group_state.commit_commit_group(commit_group)

    return DeviceOpStatus::Committed
```

**Tradeoff: single-commit_group batch vs multi-commit_group incremental add**. A multi-commit_group approach
would label the new device in commit_group N, then update existing labels in commit_group N+1.
This creates a window where the new device's label says `device_count = N+1`
but existing devices say `device_count = N`. The import protocol's majority
vote can handle this, but single-commit_group batching eliminates the window entirely
at the cost of a slightly longer commit (more label writes). Single-commit_group is
chosen for correctness simplicity.

**Tradeoff: immediate ClassMap rebuild vs lazy rebuild**. Rebuilding the
ClassMap synchronously in the add_device commit_group adds latency but guarantees the
new device is immediately available for allocation. Lazy rebuild would defer
the ClassMap update to the next allocation request, saving add_device latency
but risking allocation failures until the lazy rebuild completes. Synchronous
rebuild is chosen because device addition is an infrequent operator action.

### 2.5 Phase 5: Online device removal (NOT YET IMPLEMENTED)

```rust
// Proposed: crates/tidefs-local-object-store/src/evacuation.rs

pub struct EvacuationCursor {
    pub device_index: u32,
    pub locator_table_offset: u64,   // resumable position in locator table scan
    pub bytes_evacuated: u64,
    pub bytes_remaining: u64,
    pub state: EvacState,
}

pub enum EvacState {
    Scanning,     // Iterating locator table for references to this device
    Copying,      // Actively copying data blocks to other devices
    Updating,     // Updating locator table entries to point to new locations
    Verifying,    // Re-reading to confirm no dangling references
    Complete,     // Device has zero refcount; safe to remove
    Failed(String),
}

pub struct EvacProgress {
    pub cursor: EvacuationCursor,
    pub work_budget: WorkBudget,     // per-tick budget from #1237
    pub is_resumable: bool,
}
```

#### 2.5.1 Evacuation algorithm

```
function evacuate_device(pool, device_index, budget_per_tick):
    cursor = load_or_create_cursor(device_index)

    while cursor.state != Complete and budget_per_tick.has_remaining():
        if cursor.state == Scanning:
            // Find the next locator table entry referencing this device
            entry = locator_table.next_entry_referencing(cursor, device_index)
            if entry is None:
                cursor.state = Verifying
                continue
            cursor.current_entry = entry
            cursor.state = Copying

        if cursor.state == Copying:
            // Read data block from the evacuating device
            data = read_block(device_index, cursor.current_entry.offset, cursor.current_entry.size)
            // Allocate new block on a different device (excluding device_index)
            new_loc = pool.allocate(size=cursor.current_entry.size, exclude=[device_index])
            // Write data to new location
            write_block(new_loc.device, new_loc.offset, data)
            cursor.pending_update = (cursor.current_entry, new_loc)
            cursor.state = Updating

        if cursor.state == Updating:
            // Update locator table to point to the new location
            locator_table.update(cursor.pending_update.old, cursor.pending_update.new)
            cursor.bytes_evacuated += cursor.current_entry.size
            cursor.bytes_remaining -= cursor.current_entry.size
            cursor.state = Scanning

        save_cursor(cursor)  // checkpoint for resumability
        budget_per_tick.consume(1)

    return EvacProgress { cursor, budget_per_tick, is_resumable: true }
```

**Tradeoff: cursor-driven vs bulk evacuation**. Cursor-driven evacuation (this
design) processes one extent at a time with budget control and checkpointing.
Bulk evacuation would read all data and rewrite it in one pass — faster but
unbounded in memory and uninterruptible. Cursor-driven is chosen for
production safety: evacuation can run as a background service over
hours/days, survive restarts, and respect I/O budgets shared with foreground
traffic.

**Tradeoff: refcount gate vs scan-and-move**. The refcount gate uses the
locator table's per-extent reference counts to determine when all references
to blocks on the evacuating device have been moved. A scan-and-move approach
would iterate every extent regardless of refcounts — simpler but unaware of
shared extents (snapshots, dedup). Refcount is chosen because TideFS already
maintains refcounts for dedup and snapshots.

### 2.6 Phase 6: Device replacement, hot-spares, failure handling (NOT YET IMPLEMENTED)

```rust
// Proposed additions to device_manager.rs

pub enum SparePolicy {
    /// No automatic spare activation.
    None,
    /// Activate one spare when any data device faults.
    SingleSpare,
    /// Activate spares up to the configured redundancy level.
    RedundancyAware { max_spares: u32 },
}

pub enum DeviceFaultReason {
    IoError { error_count: u64, last_error: String },
    ChecksumError { error_count: u64 },
    Timeout { duration_ms: u64 },
    AdminRequest,
}

pub struct DeviceErrorCounter {
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
    pub error_window_start: u64,  // monotonic timestamp
    pub error_rate_threshold: u64, // errors per window before fault
}
```

#### 2.6.1 Device failure state machine

```
                     +--------+
         I/O error   | ONLINE |  error_count < threshold
         +---------->|        |<--------------------------+
         |           +---+----+                           |
         |               | error_count >= threshold       |
         v               v                                |
    +--------+      +---------+                          |
    |DEGRADED|      | FAULTED |                          |
    |        |      |         |                          |
    +---+----+      +----+----+                          |
        |                |                                |
        | rebuild        | spare activation + rebuild     |
        | complete       | or manual replace              |
        v                v                                |
    +------------------------+                            |
    |        ONLINE          |----------------------------+
    +------------------------+
       (healthy again)
```

```
function handle_io_error(device, error):
    counter = device.error_counter
    counter.record_error(error)
    if counter.within_window() and counter.exceeds_threshold():
        if device.state == ONLINE:
            device.state = DEGRADED
            emit_observability_event(DeviceStateChange {
                device: device.index,
                old_state: ONLINE,
                new_state: DEGRADED,
                reason: "error threshold exceeded",
            })
        elif device.state == DEGRADED:
            device.state = FAULTED
            emit_observability_event(DeviceStateChange {
                device: device.index,
                old_state: DEGRADED,
                new_state: FAULTED,
                reason: "continued errors while DEGRADED",
            })
            // Trigger spare activation if policy permits
            if pool.spare_policy != SparePolicy::None:
                activate_spare(pool, device)

function activate_spare(pool, faulted_device):
    spare = pool.find_available_spare(faulted_device.device_class)
    if spare is None:
        emit_observability_event(NoSpareAvailable { device: faulted_device.index })
        return
    // Replace the faulted device with the spare (Phase 6 composite operation)
    DeviceManager.replace_device(
        old_device_index = faulted_device.index,
        new_device = DeviceAddRequest { path: spare.path, device_class: spare.class, ashift: pool.ashift }
    )
```

**Tradeoff: error rate threshold vs single-error fault**. ZFS uses a single
I/O error to fault a device in most configurations (`failmode=wait`).
This design uses an error rate window (e.g., 3 errors in 60 seconds) to
avoid transient faults from cable pulls or controller resets. The threshold
is tunable per pool. Single-error fault is available as `failmode=panic` for
high-integrity deployments.

**Tradeoff: built-in spare policy vs external orchestration**. ZFS relies on
the external ZED (ZFS Event Daemon) to activate spares. This design embeds
spare activation in the DeviceManager because: (1) it eliminates an external
dependency, (2) spare activation is tightly coupled to the failure state
machine, and (3) the observability pipeline already emits events for external
orchestrators that want to override the built-in policy.


```rust
// Proposed xtask gates in tidefs-xtask

// check-pool-import-export:
//   - PoolLabelV1 encode/decode roundtrip with valid and invalid inputs
//   - Checksum verification: correct passes, corrupted fails
//   - Label L0/L1 redundancy: read from either copy, prefer newer label_commit_group
//   - Export/import roundtrip: create pool, write data, export, import, verify
//   - Export atomicity: simulate crash during label write, verify resolution
//   - Cross-system portability: export, move devices, import with new paths

// check-device-topology:
//   - topology_generation majority vote with split-generation injection
//   - device_count consistency across all labels
//   - device_index uniqueness within a pool
//   - Device add: verify device_count and topology_generation after add
//   - Device remove: verify all data accessible after evacuation + remove

// check-label-corruption:
//   - Inject checksum corruption in L0, verify import uses L1
//   - Inject checksum corruption in both L0 and L1, verify import fails cleanly
//   - Inject magic corruption, verify device is skipped by scan
```

---

## 3. Per-metaslab parallelism (explicitly deferred)

### 3.1 What is deferred

This 7-phase plan operates with **sequential, single-threaded** pool operations.
The following parallelism dimensions are explicitly deferred:

| Dimension | Current state | Target state | Tracking |
|---|---|---|---|
| Metaslab-level allocation | Single cursor, single allocator invocation | Per-metaslab allocation cursors, concurrent `allocate()` across metaslabs | #1278, #1694 |
| Concurrent device I/O | Single I/O queue per pool | Per-device I/O queues with work-stealing | metadata engine parallelism design |
| Per-core metadata accumulation | Single-threaded commit_group commit | Per-core accumulation buffers merged at commit_group commit | #1278 |
| Parallel label read during import | Sequential device scan | Concurrent `read_label()` across candidate devices | This plan — Phase 2 can adopt |

### 3.2 Why deferred

1. **Correctness first**: Sequential operations are easier to verify against
   the commit_group state machine (#1267). Adding parallelism before the sequential
   path is solid risks subtle ordering bugs at the commit_group boundary.

2. **The per-metaslab allocator already has the data structures**:
   `tidefs-pool-allocator` already maintains per-metaslab cursors, allocation
   stats, and pressure signals. The transition to parallel allocation is a
   concurrency-model change, not a data-model change.

3. **Device management is unaffected**: Add, remove, and replace operations
   modify topology metadata (labels, ClassMap). These operations are
   inherently serialized by the commit_group commit cycle. Parallelism in the
   allocator does not change the device management code path.

   (Phase 7 gates) before parallelism is introduced. This separates

### 3.3 Integration contract

When per-metaslab parallelism lands, the following integration points are
contractually stable and must not change:

- `PoolLabelV1` on-disk format (Phase 1 — sealed, done)
- `ClassMap::rebuild()` signature (Phase 2/4)
- `PoolImporter::import_pool()` return type (Phase 2)
- `PoolExporter::export_pool()` protocol (Phase 3)
- `DeviceManager::add_device()` / `remove_device()` / `replace_device()` signatures (Phases 4–6)
- `EvacuationCursor` checkpoint format (Phase 5)

The only change surface for parallelism is internal to `tidefs-pool-allocator`'s
`allocate()` and `free()` methods, which will acquire per-metaslab locks instead
of a pool-wide lock.

---

## 4. Phase dependency graph

```
Phase 1 (PoolLabelV1 types + codec) ─── DONE
    │
    ▼
    │
    ├──────────────────┐
    ▼                  ▼
Phase 3 (PoolExporter) Phase 4 (Device add)
    │                    │
    │                    ▼
    │                  Phase 5 (Device remove + evacuation)
    │                    │
    │                    ▼
    │                  Phase 6 (Replace, spares, failure handling)
    │                    │
    └────────┬───────────┘
             ▼
```

Phase 3 (export) and Phase 4 (add) are parallelizable after Phase 2 completes.
Phase 5 depends on Phase 4 (need device addition before removal). Phase 6
depends on Phases 4 and 5. Phase 7 gates all prior phases.

---

## 5. Integration contracts with adjacent subsystems

### 5.1 CommitGroup state machine (#1267)

- **Phase 2 (import)**: `PoolImporter` calls `commit_group_state.open_at(commit_group)` with the
- **Phase 3 (export)**: `PoolExporter` calls `commit_group_state.quiesce()` to gate new
  commit_group formation, then `commit_group_state.flush_all()` to drain committed commit_groups.
- **Phase 4 (add)**: `DeviceManager` opens a new commit_group, stages label updates, and
  commits. The commit_group commit is what makes the topology change durable.
- **Phase 5 (remove)**: Evacuation operates outside the commit_group cycle (it moves
  data, which generates its own commit_groups). The final `remove_device()` label update
  is a single-commit_group commit.

### 5.2 Data evacuation engine (#1239, #1229, #1241)

- **Phase 5 depends on** the cursor-driven evacuation engine for the
  `EvacuationCursor` state machine, budgeted work ticks (#1237), and
  locator table traversal.
- The evacuation engine is an independent subsystem; Phase 5 provides the
  pool-level orchestration (when to start/stop evacuation, refcount gate,
  label update after evacuation completes).

### 5.3 Spacemap allocator (#1189, #1694)

- **Phase 4 (add)**: `DeviceManager` initializes a new segment free map for the
  added device and registers it with the `PoolAllocator`.
- **Phase 5 (remove)**: `DeviceManager` de-registers the device's free map from
  the `PoolAllocator` after evacuation completes.
- Per-metaslab allocation cursors (already implemented in `tidefs-pool-allocator`)
  are used but not yet parallelized.

### 5.4 Cluster membership (#1283) and lock service (#1248)

- **Phase 7 (deferred)**: Cluster pool import requires acquiring a pool lease
  via the distributed lock service and registering the pool with cluster
  membership. These integrations are deferred to Phase 7 wire-up issues.

---

## 6. Tradeoff summary

| Decision | Alternative | Rationale |
|---|---|---|
| Fixed 255-byte pool name | Variable-length encoding | Simpler checksum boundary, negligible waste (<0.1% of 256 KiB label) |
| BLAKE3-256 | SHA-256, BLAKE2 | 3× faster, tree-hashing for future incremental updates |
| Directory scan import | Config-file cache | Labels are source of truth; cache is performance optimization, deferred |
| Majority vote for topology_generation | Strict consistency | Handles partial-label-write crash cases; force_import escape hatch |
| Offline-only export | Online export | Simpler quiesce model; online export deferred to future design |
| Two-label copies (L0/L1) | Single label copy | Crash resilience: import resolves split labels via label_commit_group |
| Single-commit_group batch for device add | Multi-commit_group incremental | Eliminates transient inconsistency window |
| Synchronous ClassMap rebuild | Lazy rebuild | Infrequent operator action; immediate availability > latency |
| Cursor-driven evacuation | Bulk evacuation | Resumable, budgeted, production-safe for large devices |
| Refcount gate for removal | Scan-and-move | Correct for shared extents (snapshots, dedup) |
| Error rate threshold for faults | Single-error fault | Avoids transient faults; threshold is tunable |
| Built-in spare policy | External ZED-like daemon | Eliminates external dependency; external override via observability events |
| Sequential operations (deferred parallelism) | Immediate parallelism | Correctness-first; per-metaslab data structures already in place |

---

## 7. Phase completion criteria

Each phase is complete when:

1. **Source changes** are merged to `master` in the target crate(s).
2. **Unit tests** pass for the phase's data structures and algorithms.
3. **Integration tests** (where applicable) pass: export/import roundtrip,
   device add/remove, failure injection.
4. **xtask gate** (Phase 7) passes for the cumulative set of implemented phases.
5. **Forgejo issue** for the phase is closed with a comment containing the
   commit SHA, commands run, result, and residual risk.
6. **STATUS.md** is updated with the phase completion entry.
7. **FEATURE_MATRIX.md** is updated when capability state changes.

---

## 8. References

- Canonical design: [`pool-import-export-device-topology-management.md`](pool-import-export-device-topology-management.md)
- CommitGroup state machine: [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267)
- Data evacuation: [#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239)
- Budgeted scheduling: [#1237](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1237)
- Cluster membership: [#1283](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1283)
- Distributed lock service: [#1248](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1248)
- Metadata engine parallelism: [#1278](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1278)
- Pool allocator (G2+ multi-device): [#1694](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1694)
- Spacemap allocator design: [#1189](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1189)
