# Pool Import/Export and Online Device Topology Management — Design Specification

**Issue**: [#1784](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1784)
**Canonical design**: [`docs/design/pool-import-export-device-topology-management.md`](pool-import-export-device-topology-management.md) (sealed via #2078)
**Status**: design-spec
**Maturity**: design-spec — Rust implementation deferred to wire-up issues
**Lane**: storage-core
**Kind**: design
**Hard-gate**: yes
**Crate targets**: `tidefs-local-object-store` (Pool, Device, ClassMap, PoolImporter, PoolExporter, DeviceManager), `tidefs-types-pool-label-core` (PoolLabelV1 — implemented), `tidefs-pool-allocator` (per-metaslab cursors — implemented)

---

## 0. Purpose and scope

This document is the design specification for #1784 covering pool import/export
and online device topology management. It defines the architecture, data
structures, algorithms, and tradeoffs for the TideFS pool subsystem. The
canonical sealed design at
[`pool-import-export-device-topology-management.md`](pool-import-export-device-topology-management.md)
(#2078) is the single authoritative reference for the on-device label format,
pool-state machine, and implementation plan. This document provides a
standalone, issue-scoped entry point with Rust type layouts, algorithm
pseudocode, and tradeoff analysis grounded in the existing crate
implementations.

**Implementation status mapping**:

| Component | Crate | Status |
|---|---|---|
| PoolLabelV1 (on-device label) | `tidefs-types-pool-label-core` | Implemented |
| Pool, Device, ClassMap, DeviceImpl | `tidefs-local-object-store` | Implemented |
| PoolAllocator (per-metaslab) | `tidefs-pool-allocator` | Implemented |
| PoolExporter (quiesce/flush/write_labels) | Deferred | Wire-up issue |
| DeviceManager (add/remove/replace/spare) | Deferred | Wire-up issue |
| Cluster-aware pool ownership (lease/fencing) | Deferred | Wire-up issue |

---

## 1. Architecture overview

```
+----------------------------------------------------------------------+
|                        TideFS Pool Stack                               |
+----------------------------------------------------------------------+
|                                                                       |
|  +----------------+  +----------------+  +-------------------------+  |
|  |  PoolImporter  |  |  PoolExporter  |  |     DeviceManager       |  |
|  |                |  |                |  |                         |  |
|  | scan_devices() |  | export()       |  | add_device()            |  |
|  | group_by_guid()|  | quiesce_io()   |  | remove_device()         |  |
|  | resolve_state()|  | write_labels() |  | activate_spare()        |  |
|  | open()         |  | verify_export()|  | evacuate_device()       |  |
|  +-------+--------+  +-------+--------+  +-----------+-------------+  |
|          |                   |                       |                |
|          v                   v                       v                |
|  +------------------------------------------------------------------+  |
|  |                           Pool                                     |  |
|  |  +------------+  +---------------+  +------------+                |  |
|  |  |  ClassMap  |  |  Device[0..N]   |  | PoolHealth |                |  |
|  |  | IoClass    |  |               |  |            |                |  |
|  |  |  ->devices   |  +-------+-------+  +------------+                |  |
|  |  +------------+          |                                         |  |
|  |              +-----------+-----------+                             |  |
|  |              v           v           v                             |  |
|  |       SingleDevice   MirrorDevice   Encrypted/Compressed               |  |
|  |              |           |           |                             |  |
|  |              +-----------+-----------+                             |  |
|  |                          v                                         |  |
|  |                  LocalObjectStore                                   |  |
|  +------------------------------------------------------------------+  |
|                                                                       |
|  +------------------------------------------------------------------+  |
|  |                    On-Device Layer                                  |  |
|  |  +--------------------+  +--------------------+                    |  |
|  |  |  PoolLabelV1 L0    |  |  PoolLabelV1 L1    |                    |  |
|  |  |  (offset 0)        |  |  (end - 256 KiB)   |                    |  |
|  |  +--------------------+  +--------------------+                    |  |
|  +------------------------------------------------------------------+  |
+----------------------------------------------------------------------+
```

### 1.1 Layer responsibilities

- **PoolLabelV1**: 256 KiB on-device label at two offsets per device. Contains
  pool GUID, device GUID, pool name, state, topology generation, device class,
  feature flags, and BLAKE3-256 checksum. Fully implemented in
  `tidefs-types-pool-label-core`.

- **Pool**: Top-level storage container owning a collection of `Device`
  instances. Routes I/O by `IoClass` to `DeviceClass` via `ClassMap`.
  Supports online device add/remove. Implemented in `tidefs-local-object-store`.

- **Devices**: Abstract storage devices implementing `DeviceImpl` trait. Concrete
  types: `SingleDevice` (one `LocalObjectStore`), `MirrorDevice` (N-way mirror),
  `CompressedDevice` (zstd wrapper), `EncryptedDevice` (ChaCha20-Poly1305 wrapper).
  Implemented in `tidefs-local-object-store`.

- **PoolImporter**: Scans devices for valid PoolLabelV1 instances, groups by
  device count), resolves split-state on crash recovery, and opens the pool.
  Deferred to wire-up issue.

- **PoolExporter**: Quiesces I/O, flushes all devices, writes exported state to
  labels atomically, and verifies the export. Deferred to wire-up issue.

- **DeviceManager**: Online device addition, removal, replacement, and
  hot-spare activation. Coordinates label updates with commit_group-consistent writes.
  Deferred to wire-up issue.

### 1.2 Crate dependency graph

```
tidefs-types-pool-label-core  (no_std, on-disk label types)
        |
        v
tidefs-local-object-store  (Pool, Device, DeviceImpl, ClassMap)
        |
        +-- tidefs-spacemap-allocator
        |         |
        |         v
        +-- tidefs-pool-allocator  (per-metaslab cursors, pressure)
```

---

## 2. Data structures

### 2.1 PoolLabelV1 — on-device label (implemented)

```rust
/// 256 KiB on-device label with BLAKE3-256 checksum.
/// Two copies per device: L0 at offset 0, L1 at offset capacity - 256 KiB.
#[repr(C)]
pub struct PoolLabelV1 {
    pub magic: [u8; 4],              // b"VBFS"
    pub version: u32,                // 1
    pub pool_guid: [u8; 16],         // Unique pool identifier
    pub device_guid: [u8; 16],       // Unique device identifier
    pub pool_name: [u8; 256],        // UTF-8, pool_name_len valid bytes
    pub pool_name_len: u8,
    pub pool_state: u8,              // PoolState: Active=0, Exported=1, Destroyed=2
    pub commit_group: u64,                    // Transaction group at label write
    pub topology_generation: u64,    // Monotonic counter for topology changes
    pub device_index: u32,           // 0-based index within pool
    pub device_count: u32,           // Total devices in pool
    pub device_class: u8,            // DeviceClass enum
    pub device_capacity_bytes: u64,
    pub system_area_pointer: u64,    // Offset to system area (reserved)
    pub system_area_size: u64,
    pub features_incompat: u64,      // Bitmask of incompatible features
    pub features_ro_compat: u64,     // Bitmask of read-only-compatible features
    pub features_compat: u64,        // Bitmask of compatible features
    pub checksum: [u8; 32],          // BLAKE3-256 over all preceding fields
}
```

**Label wire size**: 512 bytes (payload) padded to 256 KiB on disk.

**Label operations** (all implemented, `no_std` compatible):
- `seal_label(label) -> SealedLabel`: compute BLAKE3-256 checksum
- `encode_label(sealed, &mut [u8]) -> Result<()>`: serialize to wire format
- `decode_label(&[u8]) -> Result<SealedLabel>`: deserialize and verify
- `verify_label_checksum(&SealedLabel) -> bool`: checksum-only verification

**Error type**: `LabelError` covers `BadMagic`, `UnsupportedVersion(u32)`,
`ChecksumMismatch`, `BufferTooSmall`.

### 2.2 Pool — top-level container (implemented)

```rust
pub struct Pool {
    config: PoolConfig,
    properties: PoolProperties,
    classes: Vec<DeviceClass>,       // Per-device class assignment
    devices: Vec<Device>,                // Wrapper around Box<dyn DeviceImpl>
    class_map: ClassMap,             // IoClass -> Vec<device_index>
    health: PoolHealth,
}

pub struct PoolConfig {
    pub name: String,
    pub root_path: PathBuf,
    pub devices: Vec<DeviceConfig>,
}

pub struct PoolProperties {
    pub ashift: u8,                  // Block alignment shift (default: 12 = 4 KiB)
    pub autoexpand: bool,
    pub failmode: FailMode,
}
```

**PoolHealth states**: `Online`, `Degraded`, `Faulted`, `Suspended`.
**FailMode policies**: `Wait` (default), `Continue`, `Panic`.

### 2.3 Device — virtual device abstraction (implemented)

```rust
pub enum DeviceKind {
    Single { path: PathBuf },
    Mirror { paths: Vec<PathBuf> },
}

pub enum DeviceClass { Data, Metadata, IntentLog, ReadCache, Special, Spare }
pub enum IoClass { Data, Metadata, IntentLog, ReadCache }
pub enum DeviceState { Online, Degraded, Faulted, Offline, Removed }
```

**DeviceImpl trait** — fully implemented for all concrete types:
`SingleDevice`, `MirrorDevice`, `CompressedDevice`, `EncryptedDevice`.

Wrapper ordering: `InnerDevice -> EncryptedDevice -> CompressedDevice`
(encrypt before compress, to avoid CRIME-style side channels).

### 2.4 ClassMap — I/O routing table (implemented)

```rust
struct ClassMap {
    data: Vec<usize>,        // DeviceClass::Data device indices
    metadata: Vec<usize>,    // DeviceClass::Metadata|Special then Data fallback
    intent_log: Vec<usize>,  // DeviceClass::IntentLog then Data fallback
    read_cache: Vec<usize>,  // DeviceClass::ReadCache then Data fallback
}
```

`build_class_map()` constructs the routing table at pool creation and on device
add/remove. IntentLog writes fan out to all matching devices; all other classes
route to a single device by deterministic key hash.

### 2.5 PoolAllocator — per-metaslab allocation (implemented)

```rust
pub struct PoolAllocator {
    free_map: SegmentFreeMap,
    metaslab_count: u32,
    metaslab_size: u32,          // Segments per metaslab = 4096
    cursors: Vec<u64>,           // Per-metaslab allocation cursor
    round_robin: RoundRobinState,
    pressure_threshold: f64,     // 0.95 = 95%
    under_pressure: bool,
    last_pressure_event: Option<SpacePressureEvent>,
}
```

**Key invariants**:
1. Per-metaslab cursors advance monotonically, wrapping within metaslab boundary
2. Metaslab selection: pick non-empty metaslab with fewest free segments;
   round-robin tiebreak
3. Pressure events fire on rising/falling edge crossing (95% threshold), never
   on repeated queries while already in same state
4. Errors forward `FreeMapError` faithfully — no information loss

### 2.6 Import/export types (deferred)

```rust
/// Result of a device scan during import.
pub struct DeviceScanEntry {
    pub path: PathBuf,
    pub label: PoolLabelV1,
    pub label_location: LabelLocation,  // L0 or L1
    pub label_commit_group: u64,
}

/// Group of devices belonging to the same pool.
pub struct PoolCandidate {
    pub pool_guid: [u8; 16],
    pub pool_name: String,
    pub devices: Vec<DeviceScanEntry>,
    pub topology_generation: u64,  // Majority-vote resolved
    pub device_count: u32,         // Majority-vote resolved
    pub pool_state: PoolState,
    pub resolution: ImportResolution,
}

/// Outcome of label consistency resolution.
pub enum ImportResolution {
    Consistent,
    TopologySplit { majority_count: usize, total: usize },
    PotentiallyActive { last_commit_group: u64 },
    RecoveryNeeded { missing_devices: usize },
    Destroyed,
}

/// Import mode.
pub enum ImportMode {
    Normal,    // Requires clean or exported state
    Force,     // Bypass split-state checks (dangerous)
    ReadOnly,  // For recovery or inspection
}
```

---

## 3. Algorithms

### 3.1 Pool import algorithm

```
function import_pool(search_paths, mode) -> Pool:
    // Phase 1: Scan all devices for valid labels
    entries = []
    for path in search_paths:
        for device in block_devices(path):
            label = read_best_label(device)  // prefer L0, fallback L1, prefer newer commit_group
            if label.valid():
                entries.push(DeviceScanEntry { path: device, label, ... })

    // Phase 2: Group by pool_guid
    candidates = group_by(entries, |e| e.label.pool_guid)
    if candidates.empty():
        return Err(NoPoolsFound)

    for candidate in candidates:
        // 3a. Majority-vote topology_generation
        gen_votes = count_votes(candidate.devices, |d| d.label.topology_generation)
        candidate.topology_generation = majority(gen_votes)

        // 3b. Majority-vote device_count
        count_votes = count_votes(candidate.devices, |d| d.label.device_count)
        candidate.device_count = majority(count_votes)

        // 3c. Check for split topology
        if gen_votes.has_disagreement() or count_votes.has_disagreement():
            candidate.resolution = TopologySplit { ... }

        // 3d. Check pool state
        match candidate.pool_state:
            Destroyed => candidate.resolution = Destroyed
            Active => candidate.resolution = PotentiallyActive { ... }
            Exported => candidate.resolution = Consistent

    // Phase 4: Select best candidate and open
    candidate = select_best(candidates)
    pool = Pool::open(candidate_to_config(candidate))
    return pool
```

### 3.2 Pool export algorithm

```
function export_pool(pool) -> ():
    // Phase 1: Quiesce I/O
    pool.quiesce_io()              // Block new writes, drain in-flight
    pool.wait_pending_commit_group()        // Wait for current commit_group to commit

    // Phase 2: Flush all devices
    for device in pool.devices:
        device.sync_all()

    // Phase 3: Atomic label write (two-phase per device)
    export_commit_group = pool.current_commit_group()
    for (i, device) in pool.devices:
        label = build_export_label(pool, i, export_commit_group)
        sealed = seal_label(label)
        write_label_at_offset(device, 0, sealed)           // L0
        write_label_at_offset(device, capacity - 256KiB, sealed)  // L1

    // Phase 4: Verify export on all devices
    for device in pool.devices:
        label = read_label(device)
        assert(label.pool_state == Exported)
        assert(label.commit_group == export_commit_group)
```

### 3.3 Online device addition

```
function add_device(pool, config) -> ():

    new_device = Device::open(config)
    new_index = pool.devices.len()

    // Write initial labels on new device
    label = build_device_label(pool, new_index, pool.devices.len() + 1)
    write_both_labels(new_device, label)

    // Join pool
    pool.devices.push(new_device)
    pool.classes.push(config.class)
    pool.class_map = build_class_map(&pool.classes)

    // Update labels on all existing devices (commit_group-consistent batch)
    for (i, device) in pool.devices:
        label = build_device_label(pool, i, pool.devices.len())
        label.topology_generation += 1
        write_both_labels(device, label)

    emit_event(DeviceAdded { device_index: new_index, ... })
```

### 3.4 Online device removal

```
function remove_device(pool, device_path) -> ():
    index = find_device_by_path(pool, device_path)
    target = pool.devices[index]

    // Evacuate data (delegated to evacuation engine)
    if target.class.is_data_bearing():
        evacuate_device(pool, index)
    verify_device_empty(target)
    verify_refcount_zero(target)

    // Remove from pool
    pool.devices.remove(index)
    pool.classes.remove(index)
    pool.class_map = build_class_map(&pool.classes)

    // Update labels on remaining devices
    for (i, device) in pool.devices:
        label = build_device_label(pool, i, pool.devices.len())
        label.topology_generation += 1
        write_both_labels(device, label)

    emit_event(DeviceRemoved { device_path, ... })
```

### 3.5 Device replacement (mirror)

```
function replace_device(pool, old_path, new_config) -> ():
    add_device(pool, new_config)
    new_index = pool.devices.len() - 1
    rebuild_mirror_member(pool, old_index, new_index)
    remove_device(pool, old_path)
```

### 3.6 Hot-spare activation

```
function activate_spare(pool, faulted_device) -> ():
    spare_index = find_spare(pool, faulted_device.class)
    spare = pool.devices[spare_index]
    spare.class = faulted_device.class
    pool.classes[spare_index] = faulted_device.class
    rebuild_onto_spare(pool, faulted_device, spare)
    pool.devices[faulted_index].state = Faulted
    emit_event(SpareActivated { ... })
```

### 3.7 Device failure state machine

```
                +----------+
                |  ONLINE  |
                +----+-----+
                     | I/O error threshold reached
                     v
                +----------+
                | DEGRADED |---- I/O errors continue -------+
                +----+-----+                                |
                     | all paths fail                       |
                     v                                      v
                +----------+                          +----------+
                | FAULTED  |                          |  OFFLINE |
                +----------+                          +----------+
                     |                                      |
                     | admin replace                        | admin online
                     v                                      v
                +----------+                          +----------+
                | REMOVED  |                          |  ONLINE  |
                +----------+                          +----------+
```

**Transition rules**:
- ONLINE -> DEGRADED: `write_errors + checksum_errors >= threshold` on any mirror member
- DEGRADED -> FAULTED: all mirror members report errors, or single device fails completely
- ONLINE/DEGRADED -> OFFLINE: explicit admin action
- OFFLINE -> ONLINE: explicit admin action, device passes health check
- FAULTED/OFFLINE -> REMOVED: explicit admin removal
- DEGRADED -> ONLINE: all errors cleared, health check passes

### 3.8 Label redundancy and crash recovery

Each device carries two label copies: L0 at offset 0, L1 at offset
`capacity - 256 KiB`. On import, both are read; the copy with higher
`label_commit_group` is preferred. If one copy has a checksum mismatch, the other
is used transparently. If both are corrupt, the device is marked for recovery.

**Crash during export**:
- Crash after L0 write, before L1: L0 has `Exported` state with higher commit_group;
  import prefers L0 -> clean import.
- Crash before L0 write: both labels have `Active` state; import sees
  `PotentiallyActive` -> requires force flag or cluster lease check.

---

## 4. Tradeoffs

### 4.1 Label size: 256 KiB vs smaller alternatives

**Choice**: 256 KiB per label copy, informed by ZFS prior art.

**Design benefit target**: room for future expansion; alignment-friendly
(matches common device block sizes); straightforward fixed-size read/write.

**Tradeoffs**: 512 KiB total label overhead per device (negligible on
modern devices).

**Alternatives considered**: 4 KiB label (too small for rich topology
metadata); variable-length label (complicates atomic update); GPT-integrated
metadata (breaks raw-device usage).

### 4.2 Two-copy redundancy vs three or four

**Choice**: Two label copies (L0, L1) per device.

**Why not four** (ZFS uses four): Two copies provide sufficient redundancy
(the probability of losing both first and last 256 KiB to independent
corruption is extremely low). Simpler atomic update protocol with fewer fsync
calls during export.

**Why not one**: single point of failure for label corruption.

### 4.3 Majority-vote topology resolution vs quorum-based

**Choice**: Majority vote among device labels for `topology_generation` and
`device_count` on import.

**Design benefit target**: self-contained operation without external
coordination; simple to implement and reason about; handles partial device
failure through explicit import rules.

**Tradeoffs**: even-split scenarios require operator intervention; no
protection against a majority of devices having stale labels from a partial
topology change that crashed.

**Alternatives considered**: quorum-based (Paxos/Raft over labels) — massive
complexity for rarely exercised path; epoch-based with cluster coordinator —
adds cluster dependency for standalone pools.

### 4.4 Online device removal: evacuation vs lazy reclamation

**Choice**: Eager evacuation before device removal.

**Design benefit target**: clean and immediate removal; device can be
physically detached after removal; no residual references; aligns with
operator expectations from label-driven storage workflows.

**Tradeoffs**: evacuation can take a long time for large devices; requires
the evacuation engine (#1239) to be implemented first.

**Alternatives considered**: lazy reclamation, as seen in distributed-storage
prior art, adds long-lived "zombie" device state, complicates crash recovery,
and risks data loss if a device is physically detached before reclamation
completes.

### 4.5 Cluster-aware pool ownership: lease vs lock service

**Choice**: Pool lease with fencing on expiry (deferred to wire-up).

**Design benefit target**: simple one-node-owns-at-a-time model; compatible with
standalone mode (lease check is a no-op when not clustered); fencing
guarantees no split-brain writes.

**Tradeoffs**: lease renewal adds periodic overhead; fencing requires
cluster membership (#1283) and distributed lock service (#1248).

### 4.6 Device wrapper ordering: encrypt-then-compress vs compress-then-encrypt

**Choice**: Encrypt before compress (`InnerDevice -> EncryptedDevice -> CompressedDevice`).

**Design benefit target**: no metadata leakage through compression ratio side
channels (CRIME/BREACH-style attacks); correct security posture.

**Tradeoffs**: compression provides no space savings for encrypted data;
users who want both should use filesystem-level compression before encryption.

**Decision**: security trumps space efficiency.

---

## 5. Integration contracts

### 5.1 Transaction group (commit_group) integration

- Label writes always occur within a commit_group; `label_commit_group` records the commit_group at
  write time
- Export quiesce: `wait_pending_commit_group()` ensures current commit_group commits before
  label writes
- Device add: label updates for all devices are commit_group-consistent (all or none)

### 5.2 Spacemap allocator integration

`PoolAllocator` wraps `SegmentFreeMap` with per-metaslab cursors (Phase 6
complete). Multi-device allocation coordination deferred to G2+
(`MULTI_DEVICE_ALLOCATOR_COORDINATION_DEFERRED` gate marker).

### 5.3 Cluster membership integration

Pool import in cluster mode requires: membership service (#1283), distributed
lock service (#1248) for pool lease, ADMIN service (#1243) for state broadcast.
Standalone pools bypass all three.

### 5.4 Data evacuation engine

Device removal delegates data movement to evacuation engine (#1239, #1229,
#1241). Pool subsystem provides `evacuate_device()` entry point,
`verify_device_empty()` post-check, and budgeted I/O scheduling (#1237).

### 5.5 Observability

All state transitions emit events: `DeviceAdded`, `DeviceRemoved`,
`DeviceReplaced`, `SpareActivated`, `PoolStateChanged`, `DeviceStateChanged`,
`PoolHealthChanged`, `ImportCompleted`, `ExportCompleted`.

---

## 6. Error handling

### 6.1 Import-time errors

| Error | Cause | Recovery |
|---|---|---|
| `NoPoolsFound` | No valid labels on any scanned device | Verify device paths |
| `PoolDestroyed` | Pool state is `Destroyed` | Restore from backup |
| `TopologySplit` | Labels disagree on topology | Force import (`-F`) or manually resolve |
| `MissingDevices` | Fewer devices than `device_count` | Attach missing devices or force import |
| `LabelCorrupt` | Both L0 and L1 checksums fail | Replace device |
| `PoolActive` | Pool is `Active` on another node | Cluster fence or force import |

### 6.2 Runtime errors

| Error | Cause | Recovery |
|---|---|---|
| `NoHealthyDevices` | All devices for an IoClass faulted | Replace faulted devices |
| `DeviceFaulted` | I/O error threshold exceeded | Device transitions to DEGRADED or FAULTED |
| `NoSpace` | PoolAllocator returns NoFreeSegments | Add devices, compact, or free space |
| `MirrorDegradedWrite` | Some mirror members failed write | Read succeeded on remaining members |
| `EvacuationFailed` | Device evacuation interrupted | Resume from persistent cursor |

---

## 7. Testing strategy

### 7.1 Unit tests (existing)

- `tidefs-types-pool-label-core`: encode/decode roundtrip, checksum verification,
  pool name truncation, buffer-too-small errors
- `tidefs-pool-allocator`: allocation exhaustion, pressure enter/exit/reenter,
  no-double-pressure-event, metaslab cursor maintenance through exhaustion,
  full propagation chain

### 7.2 Integration tests (existing)

- `tidefs-local-object-store`: pool create/open, put/get/delete with IoClass
  routing, multi-device deterministic routing, device add/remove, health computation,
  mirror read/write/delete degraded-path, pool store reborrow

### 7.3 Planned tests (deferred with implementation)

- Export/import roundtrip with checksum verification
- Export atomicity (crash during label write)
- Device add: topology_generation and device_count consistency
- Device remove: evacuation + label update
- Device replace (mirror): rebuild + data integrity
- Hot-spare: auto-activation on fault
- Failure handling: I/O error injection -> state transitions + events
- Cross-system portability: export -> move devices -> import

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Label write atomicity violation on crash | Medium | High | Two-copy redundancy, import-time state resolution, label_commit_group disambiguation |
| Split topology generation after partial add/remove | Low | Medium | Majority-vote on import, -F force-import escape hatch |
| Evacuation cursor fails mid-operation | Medium | Medium | Persistent cursor state, resumable after restart, budgeted per tick |
| Cluster lease expiry during active I/O | Low | High | Fencing on expiry, write-side lease check before commit_group commit |
| Label format version mismatch across cluster | Low | Medium | Feature flag bits, version negotiation, read-only fallback |
| Device class forward-compatibility gap | Low | Low | Unknown(u8) variant treated as generic data device |
| Mirror rebuild interrupted | Medium | Medium | Resume from last rebuilt segment; checksum-based incremental repair |

---

## 9. Non-claims (explicit boundaries)

- Data evacuation engine implementation -> #1239, #1229, #1241
- Erasure coding redundancy and rebuild algorithms -> #1249
- ADMIN service protocol and replicated commit_group commit -> #1243, cluster design suite
- Multi-device allocation and I/O scheduling -> respective deferred issues
- Pool geometry conversion (mirror <-> erasure coding) -> #1275
- Per-metaslab parallelism in the allocator -> metadata engine parallelism design (#1278)

---

## 10. References

- Canonical sealed design: `pool-import-export-device-topology-management.md` (#2078)
- Implementation plan companion: `1971-pool-import-export-7-phase-implementation-plan.md` (#1971)
- Earlier design-spec: `1813-pool-import-export-device-topology-management-design.md` (#1813)
- Original design: `POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` (#1254)
- CommitGroup state machine: #1267
- Cluster membership: #1283
- Distributed lock service: #1248
- Data evacuation engine: #1239
- Budgeted scheduling: #1237
- Spacemap allocator: #1189, #1694
