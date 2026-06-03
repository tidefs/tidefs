# Pool Import/Export and Online Device Topology Management Design (P1 hard-gate)

Maturity: **design-spec** for the pool label format, import/export protocol,
online device addition/removal/replacement, device failure handling, hot-spare
auto-replace, and cluster-aware pool ownership semantics.

This document closes Forgejo issue #1254.

## 1. Motivation

Production storage systems must survive hardware reconfiguration without data
loss or external configuration databases. ZFS handles this well: `zpool import`
scans devices, discovers pool topology from on-device labels, and reconstructs
pool state. Ceph takes a fundamentally different approach: OSDs join a monitor
cluster that holds the topology map centrally.

tidefs must support both standalone pools (ZFS-like portability) and
cluster-attached pools (Ceph-like coordination) through a unified label-driven
discovery protocol. Online device management — adding, removing, replacing, and
handling failed devices while the pool is live — is table-stakes for production
storage and a hard requirement for the "better than ZFS/Ceph" standard.

ZFS limitations this design addresses:

- ZFS device removal is a recent addition (post-0.8.0) and remains limited
  (mirror device removal only; PARITY_RAID removal requires pool-wide remapping).
- ZFS device replacement requires manual `zpool replace`; no built-in hot-spare
  auto-activation without external `zed` scripting.
- ZFS pool export requires unmounting all datasets; online export is not
  supported.
- ZFS label format couples topology to device hierarchy; tidefs decouples label
  discovery from internal tree structure.

## 2. Relationship to Existing Types

| Current state | This design | Integration point |
|---|---|---|
| `PoolRecord` in local object store (pool guid, name) | `PoolLabelV1` on-device label: self-describing, topology-aware | System area bootstrap reads labels before opening pool |
| `DeviceTree` in local allocator (device topology, segment sizing) | `topology_generation` counter, `device_count` field in label | Allocator rebuilds from label topology on import |
| `LocalFileSystem` pool open path (single-device assumption) | Multi-device pool open: scan, group, verify, open | `PoolImporter::import_pool()` replaces direct open |
| CommitGroup state machine (#1267) per-pool commit ordering | Label commit_group: last committed commit_group on each device; import selects max | Label write piggybacks on commit_group commit cycle |
| Cluster membership (#1283, #1217) separate from pool ownership | Pool ownership: node-imported or cluster-shared; membership is orthogonal | Pool import clears cluster membership; rejoin required |

## 3. Pool Label Format

### 3.1 PoolLabelV1 record

Each device in a pool carries a self-describing label that identifies the pool,
the device's role, the topology generation, and the recovery point.

```
PoolLabelV1 {
    magic: [u8; 4],            // "VBFS"
    version: u32,              // label format version (1)
    pool_guid: [u8; 16],       // unique pool identifier (UUID v4)
    device_guid: [u8; 16],     // unique device identifier (UUID v4)
    pool_name_len: u16,        // length of pool_name field
    pool_name: [u8; pool_name_len], // human-readable pool name (UTF-8)
    pool_state: PoolState,     // ACTIVE(0), EXPORTED(1), DESTROYED(2)
    commit_group: u64,                  // last committed commit_group on this device
    label_commit_group: u64,            // commit_group when this label was last written
    device_index: u32,         // device position in topology (0-based)
    topology_generation: u64,  // incremented on each device add/remove
    device_count: u32,         // total devices in pool topology
    device_class: DeviceClass, // HDD(0), SSD(1), NVME(2), LOG_DEVICE(3), CACHE(4), SPECIAL(5)
    device_capacity_bytes: u64, // total device capacity
    system_area_pointer: u64,  // byte offset to system area root
    system_area_size: u64,     // size of system area in bytes
    features_incompat: u64,    // bitmask: incompatible feature flags
    features_ro_compat: u64,   // bitmask: read-only-compatible feature flags
    features_compat: u64,      // bitmask: compatible feature flags
    checksum: [u8; 32],        // BLAKE3-256 of all preceding fields
}
```

Total fixed-size portion: 122 bytes (before pool_name and alignment).

### 3.2 Label placement

Labels are written to two locations per device for redundancy:
- **Label 0**: first 256 KiB of the device (offset 0)
- **Label 1**: last 256 KiB of the device (offset `device_capacity_bytes - 256KiB`)

Each label copy is self-contained and independently verifiable. On read, both
are checked; either valid copy suffices. The `label_commit_group` field disambiguates
which copy is newer when both are valid.

### 3.3 PoolState transitions

```
         +---------+
    +--->| ACTIVE  |<--- import
    |    +----+----+
    |         |
    |         v export
    |    +----+----+
    +----|EXPORTED |
    |    +----+----+
    |         |
    |         v destroy
    |    +----+----+
    +----|DESTROYED| terminal state
         +---------+
```

- ACTIVE → EXPORTED: all commit_group state flushed, labels written synchronously to all devices.
- EXPORTED → ACTIVE: import succeeds; pool is live.
- EXPORTED → DESTROYED: user explicitly destroys pool; labels marked DESTROYED, data is unreachable.
- ACTIVE → DESTROYED: only valid when pool is forcibly destroyed (operator confirmation required).

## 4. Pool Import Algorithm

### 4.1 Device scan

```
PoolImporter::scan_candidates(device_paths: &[PathBuf]) -> Vec<CandidatePool>
```

1. Open each candidate device.
2. Read Label 0 (first 256 KiB); check magic "VBFS".
3. If Label 0 invalid, read Label 1 (last 256 KiB).
4. Verify label checksum (BLAKE3-256).
5. Reject devices with `pool_state == DESTROYED`.
6. Group devices by `pool_guid` into `CandidatePool` structs.


For each `CandidatePool`:
1. Check that `device_count` matches the count of discovered devices. If fewer
   devices found: pool is DEGRADED; import requires `--force` or explicit
   confirmation.
2. Verify all devices share the same `topology_generation`. Mismatch indicates
   an interrupted device add/remove operation; import selects the majority
   generation and marks minority devices as stale (to be re-labeled on next
   commit_group commit).
3. Verify label checksums on all devices.
4. Select the recovery commit_group: `max(commit_group)` across all valid devices.
5. Sort devices by `device_index` for topology reconstruction.

### 4.3 Recovery point selection

- The highest `commit_group` across all devices is the recovery point.
- Any device with `commit_group < recovery_commit_group` replays from the intent log (#1252) to
  catch up.
- If no intent log exists or replay fails for a device: the device is marked
  stale and re-initialized (data loss on that device only; pool-level
  redundancy may cover it).

### 4.4 System area bootstrap

1. From the device with the highest `commit_group`, read `system_area_pointer` and
   `system_area_size`.
2. Open the system area: locate the most recent checkpoint.
4. If the checkpoint is corrupt on the primary device, fall back to another
   device's system area pointer (they may differ if a commit_group was partially
   committed).

### 4.5 Cross-system import

- A pool exported on host A can be imported on host B without external
  configuration.
- Device paths may differ; the label scan finds devices regardless of OS-level
  naming.
- All required topology, feature flag, and recovery information is in the
  labels.
- Cluster membership state (if any) is cleared on import; the pool must rejoin
  a cluster explicitly via admin command.
- Feature flag incompatibility: if `features_incompat` contains bits not
  recognized by the importing tidefs version, import is refused with a
  human-readable feature name list.

## 5. Pool Export Algorithm

```
PoolExporter::export_pool(pool: &Pool) -> Result<()>
```

1. **Quiesce commit_group**: advance the commit_group state machine to QUIESCE phase (#1267).
2. **Flush all dirty state**: write all pending metadata, data, and commit
   records.
3. **Sync checkpoint**: write a checkpoint pointing to the flushed state.
4. **Update labels**: on each device, set `pool_state = EXPORTED`,
   `label_commit_group = current_commit_group`, and recompute the checksum.
5. **Write both label copies**: Label 0 and Label 1 on every device (synchronous
   write, no caching).
6. **Return success** only after all device labels are confirmed written. If
   any device fails, the export is aborted and the pool remains ACTIVE.

The export is atomic: either all devices transition to EXPORTED, or the pool
stays ACTIVE. There is no intermediate state where some devices have EXPORTED
labels and others have ACTIVE labels — this would prevent re-import.

## 6. Online Device Management

### 6.1 Device addition (grow pool)

Admin: `tidefsctl pool add <pool> <device>`

**Algorithm**: `DeviceManager::add_device(pool, device_path)`

2. Write `PoolLabelV1` to the new device with:
   - Fresh `device_guid` (UUID v4).
   - `device_index = current device_count`.
   - `topology_generation = current + 1`.
   - `device_count = current + 1`.
   - `commit_group = current_commit_group`, `pool_state = ACTIVE`.
3. Write both label copies to new device.
4. **Within the same commit_group commit**: update labels on ALL existing devices to
   reflect new `device_count` and `topology_generation`.
5. Commit the commit_group. The new device participates in future allocations
   immediately.
6. Existing data is NOT rebalanced. Rebalancing is a separate BACKGROUND
   operation (#1241, #1265).
7. Device addition does not block IO. Label updates are piggybacked on the
   regular commit_group commit cycle.

### 6.2 Device removal (shrink pool)

Admin: `tidefsctl pool remove <pool> <device>`

**Algorithm**: `DeviceManager::remove_device(pool, device_index)`

2. Mark device state as REMOVING in the pool's in-memory topology.
3. **Data evacuation** (BACKGROUND lane, #1241):
   - Iterate all extent locators on the target device.
   - For each locator: allocate new space on remaining devices, copy data,
     update ExtentLocatorTable (#1285), decrement old locator refcount.
   - Cursor-driven for restart-after-interrupt (#1239).
   - Budgeted per-tick via resource governor (#1237).
4. Once evacuated (refcount of all locators on device reaches 0):
   - Mark device as REMOVED.
   - Decrement `device_count`, increment `topology_generation`.
   - Write updated labels to all remaining devices within a single commit_group.
   - Write DESTROYED labels to removed device.
5. Device can be physically detached after REMOVED state is committed.

### 6.3 Device replacement (hot-spare / manual replace)

Admin: `tidefsctl pool replace <pool> <old-device> <new-device>`

**Algorithm**: `DeviceManager::replace_device(pool, old_idx, new_path)`

1. Add new device (as in 6.1), initially as REPLACING.
2. **Direct copy evacuation**: copy all data from old device to new device
   directly (faster than general evacuation: sequential read of old device,
   sequential write to new device).
3. Update ExtentLocatorTable entries: redirect `device_id` and `physical_offset`
   to new device.
4. Once copy is complete:
   - Remove old device (as in 6.2, skip evacuation since data already moved).
   - Promote new device from REPLACING to ACTIVE.
5. If old device is already FAILED: skip the copy phase; instead use redundancy
   (erasure coding #1249 or mirror) to rebuild data onto new device.

### 6.4 Failed device handling

**Detection**: IO errors on read or write to a device trigger the failure path.

- Read error + checksum mismatch: corruption detected; try redundancy path (#1287).
- Read error + no redundancy: dataset becomes unavailable; read-only fallback
  where possible.
- Write error: device marked DEGRADED or FAILED. All further writes to that
  device are redirected.

**Failure states**:
- DEGRADED: device has transient errors but is still responding. Pool continues;
  operator is notified.
- FAILED: device is unresponsive. If redundancy is available (#1249, #1286),
  automatic rebuild begins. If not, pool enters DEGRADED mode with reduced
  redundancy; data on failed device is inaccessible.

**Operator notification**: pool state change events are emitted via the
observability pipeline (#1235 trace emission, admin event stream).

### 6.5 Auto-replace and hot-spare policy

Pool-level configuration:

```
SparePolicy {
    spare_devices: Vec<DeviceId>,     // pre-labeled spare devices
    auto_replace: bool,               // true = automatic on failure
    replace_after_seconds: u64,       // delay before auto-replace (default: 0)
    rebuild_priority: RebuildPriority,// FOREGROUND, BACKGROUND_FAST, BACKGROUND_SLOW
}
```

- Spare devices are pre-labeled with the pool's `pool_guid` and `pool_state =
  ACTIVE` but with `device_index = DEVICE_INDEX_SPARE` (a sentinel value
  indicating the device is not yet in the active topology).
- On device failure with `auto_replace = true`: the pool automatically selects
  a spare, begins the replace flow (6.3).
- Rebuild is budgeted via the resource governor (#1237) and uses the BULK plane
  (#1229) for data movement.
- The operator can declare spare devices without auto-replace; manual
  replacement is then triggered via `tidefsctl pool replace`.

## 7. Cluster Integration

### 7.1 Standalone vs cluster pool ownership

- **Standalone pool**: imported by a single node. The importing node owns the
  pool exclusively. No cross-node coordination.
- **Cluster pool**: imported by any node in the cluster. Pool ownership is
  shared; topology changes must be agreed through the ADMIN service (#1243) and
  committed via a replicated commit_group.

### 7.2 Pool import in cluster mode

1. Device labels are read locally (as in §4).
2. Cluster membership (#1283, #1217) is checked: the importing node must be a
   member of the cluster that owns the pool.
3. Pool lease is acquired via the distributed lock service (#1248).
4. If another node currently owns the pool: import is refused (STOLEN lock
   error). The operator must first export the pool on the owning node.
5. On successful import: the pool becomes available to all cluster nodes through
   VFS_RPC (#1234).

### 7.3 Topology changes in cluster mode

- Device add/remove/replace operations are proposed through ADMIN service
  (#1243).
- The proposal is committed as a replicated commit_group: all nodes apply the change.
- Label updates are written by the pool owning node; other nodes read labels on
  next pool open or label refresh.

## 8. Protocol and Compatibility

### 8.1 Feature flags

The three `features_*` bitmasks in `PoolLabelV1` follow the standard tidefs
feature flag model (#1220 §feature-flags):

- `features_incompat`: bits unknown to an older tidefs version cause import
  refusal. Used for label format changes and on-disk format breaking changes.
- `features_ro_compat`: bits unknown cause read-only import. Used for features
  where write access could corrupt older-version data.
- `features_compat`: bits unknown are ignored. Used for optional features that
  don't affect format compatibility.

Feature bits defined by this design:
- `POOL_LABEL_V1` (incompat bit 0): pool label format V1 (always set).
- `DEVICE_CLASS_AWARE` (compat bit 0): pool uses DeviceClass for allocation
  policy.
- `SPARE_POLICY_SUPPORTED` (compat bit 1): pool supports hot-spare auto-replace.

### 8.2 Label format versioning

The `version` field in `PoolLabelV1` is incremented only when the label struct
itself changes. V1 → V2 would be triggered by: field additions that change the
fixed-size prefix, magic number change, or checksum algorithm change. Feature
flags are used for pool-level capability changes within a label version.

## 9. ZFS and Ceph Comparative Analysis

| Aspect | ZFS | Ceph | tidefs (this design) |
|---|---|---|---|
| Pool discovery | On-disk labels (2 copies per device), `zpool import -d /dev` scans | OSDs join monitor; topology in monitor map | On-disk labels (2 copies per device) with direct scan; no external config needed |
| Label format | 256 KiB `device_label` with 4 copies per device, nvlist encoding | Not applicable (monitor holds topology) | 256 KiB per copy, 2 copies per device, fixed binary struct with BLAKE3-256 checksum |
| Pool export | Requires unmounting all datasets; `zpool export` flushes and writes labels | No export concept; OSDs can be taken offline individually | Online export without unmount; flush → label write → return |
| Device addition | `zpool add`; immediate participation; no rebalancing | `ceph osd create`; CRUSH map update | `tidefsctl pool add`; immediate participation; rebalancing is separate BACKGROUND op |
| Device removal | Post-0.8.0, limited (mirror only); PARITY_RAID removal requires device remap indirection | `ceph osd out`; data migrates via backfill | Full support: evacuation → refcount zero → label update; cursor-driven, restartable |
| Device replacement | `zpool replace`; resilver to new device; manual trigger | `ceph osd destroy` + `create`; backfill | `tidefsctl pool replace`; direct copy for healthy old device, rebuild for failed |
| Hot-spare | `zed` daemon (external scripting); not built into ZFS core | N/A (CRUSH handles failure via replication) | Built-in `SparePolicy` with auto-replace; no external daemon required |
| Cross-system import | `zpool import -a` finds all pools; portable | N/A (monitor model) | Label-driven import; portable; cluster membership cleared on import |
| Cluster integration | N/A (single-node) | Native (monitor cluster) | Hybrid: standalone or cluster mode; pool ownership orthogonal to membership |

## 10. Implementation Plan

### Phase 1: PoolLabelV1 type and codec (1 issue)
- Define `PoolLabelV1` struct in `tidefs-types-object-store-core`.
- Implement `encode_label` / `decode_label` with BLAKE3-256 checksum verification.

### Phase 2: PoolImporter scan and group (1 issue)
- `PoolImporter::scan_candidates()`: open devices, read labels, group by pool_guid.
- Unit tests with synthetic device images, missing-device scenarios.

### Phase 3: Pool import path (1 issue)
- Integration with LocalFileSystem open path: replace single-device assumption.
- Test: create pool, export, re-import, verify data integrity.

### Phase 4: PoolExporter (1 issue)
- `PoolExporter::export_pool()`: quiesce commit_group, flush, sync checkpoint, write labels.
- Atomicity guarantee: all-or-nothing label write.
- Test: export → import roundtrip with data verification.

### Phase 5: Device addition (1 issue)
- `DeviceManager::add_device()`: label new device, update all existing labels within commit_group.
- Integration with allocator: new device participates in allocations.
- Test: add device to pool, verify capacity increase, write data to new device.

### Phase 6: Device evacuation engine (1-2 issues)
- Cursor-driven evacuation (#1239): iterate locators, copy data, update locator table.
- Budgeted per-tick (#1237), resumable after restart.
- Test: fill device, evacuate, verify all data accessible from other devices.

### Phase 7: Device removal (1 issue)
- `DeviceManager::remove_device()`: evacuation → refcount zero → label update.
- Test: remove device, verify pool continues serving IO, verify removed device labels.

### Phase 8: Device replacement and hot-spare (1-2 issues)
- `DeviceManager::replace_device()`: add new, copy/rebuild, remove old.
- `SparePolicy`: auto-replace on failure, rebuild priority.
- Test: replace healthy device, replace failed device (with redundancy).

### Phase 9: Failed device handling (1 issue)
- IO error detection → DEGRADED/FAILED state machine.
- Operator notification via observability pipeline.
- Redundancy-based rebuild for failed devices.

### Phase 10: Cluster pool import (1-2 issues, deferred)
- Cluster membership check, pool lease acquisition.
- Replicated commit_group for topology changes.
- Test: import pool on node A, fail over to node B, verify data.

- `tidefs-xtask check-pool-import-export` gate.
- Integration tests: export/import, add/remove/replace, failure injection.


  roundtrip, import/export atomicity, device add/remove commit_group consistency.
  correctness, device_count consistency, majority-generation selection.
- Integration test: create pool with N devices, export, import on different
  paths, verify all data checksums.
- Integration test: add device, write data, remove device (with evacuation),
  verify zero data loss.
- Failure injection: simulate write failure during label write, verify
  export atomicity (all ACTIVE or all EXPORTED, no split state).

## 12. Deferred Items

- **Cluster pool import (Phase 10)**: depends on cluster membership (#1283),
  distributed lock service (#1248), and ADMIN service (#1243).
- **Online pool geometry conversion** (mirror ↔ erasure coding): tracked in
  #1275; label format supports it but algorithm is deferred.
- **Pool migration between cluster and standalone mode**: requires coordinated
  export + re-import with cluster state teardown.
- **Device firmware/health SMART integration**: useful for predictive failure
  but not a hard gate for pool management.
- **Multi-pool import ordering and dependency resolution**: pools that depend on
  each other (send/receive targets) may need ordered import; deferred to
  send/receive design (#1251).

## 13. Non-claims (explicit boundaries)

- This design does not include the data evacuation engine implementation
  (cursor-driven, bulk-plane data movement) — tracked in #1239, #1229, #1241.
- This design does not cover erasure coding redundancy or rebuild algorithms —
  tracked in #1249.
- This design does not specify the ADMIN service protocol or replicated commit_group
  commit — tracked in #1243 and cluster design suite.
- This design does not change the local filesystem's single-device I/O path;
  multi-device allocation and IO scheduling are deferred to their respective
  issues.
