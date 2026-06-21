# Pool Import/Export and Online Device Topology Management — Design Specification

**Issue**: [#1813](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1813)
**Status**: design-sealed
**Maturity**: **design-spec** — comprehensive authoritative reference for pool import/export,
  online device topology management, failure handling, hot-spare policy, and 7-phase
  implementation plan. Rust implementation deferred to wire-up issues for Phases 2–7.
**Lane**: storage-core
**Kind**: design
**Hard-gate**: yes
**Crate targets**: `tidefs-local-object-store` (Pool, Device, ClassMap, PoolImporter,
  PoolExporter, DeviceManager), `tidefs-types-pool-label-core` (PoolLabelV1 — Phase 1
  implemented), `tidefs-pool-allocator` (per-metaslab cursors — Phase 6 implemented)
**Depends on**: #1267 (commit_group state machine), #1283 (cluster membership), #1248 (distributed
  lock service), #1243 (ADMIN service), #1239/#1229/#1241 (data evacuation engine),
  #1237 (budgeted scheduling), #1189/#1694 (spacemap allocator)

---

## 0. Purpose and authority

This document is the single authoritative design specification for pool import/export and
online device topology management in TideFS. It defines the frozen on-device label format,
pool-state machine, import/export protocols, online device add/remove/replace procedures,
device failure state machine, hot-spare activation policy, cluster-aware pool ownership
model, and 7-phase implementation plan. All future implementation issues reference this
specification.

**Seal statement**: The PoolLabelV1 on-device label format, pool import/export protocols,
online device addition/removal/replacement procedures, device failure state machine,
hot-spare `SparePolicy`, cluster-aware pool ownership model, and 7-phase implementation
plan are frozen. Per-metaslab parallelism is explicitly deferred to the metadata engine
parallelism design (#1278). No further design changes to these surfaces are permitted.
Runtime implementation of individual phases is deferred to wire-up issues.

---

## 1. Architecture overview

### 1.1 Pool stack layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           TideFS Pool Stack                                │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────────────────┐ │
│  │  PoolImporter  │  │  PoolExporter  │  │       DeviceManager         │ │
│  │                │  │                │  │                             │ │
│  │ scan()         │  │ export()       │  │ add_device()                │ │
│  │ group()        │  │ quiesce()      │  │ remove_device()             │ │
│  │ recover()      │  │ write_labels() │  │ activate_spare()            │ │
│  │ open()         │  │ verify()       │  │ evacuate_device()           │ │
│  └───────┬────────┘  └───────┬────────┘  └───────────┬─────────────────┘ │
│          │                   │                       │                    │
│          ▼                   ▼                       ▼                    │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │                            Pool                                     │   │
│  │  ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────────────┐ │   │
│  │  │ ClassMap │  │  Device[0..N] │  │ DeviceKind │  │    DeviceState    │ │   │
│  │  │ IoClass  │  │             │  │ Single   │  │    Online       │ │   │
│  │  │  →devices  │  │ ┌─────────┐ │  │ Mirror   │  │    Degraded     │ │   │
│  │  │          │  │ │DeviceImpl │ │  │          │  │    Faulted      │ │   │
│  │  └──────────┘  │ └─────────┘ │  └──────────┘  │    Offline      │ │   │
│  │                └─────────────┘                │    Removed      │ │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│          │                                                               │
│          ▼                                                               │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │                    On-Device PoolLabelV1                            │   │
│  │  L0 (offset 0, 256 KiB)     L1 (offset capacity-256 KiB, 256 KiB)  │   │
│  │  ┌─────────────────────┐    ┌─────────────────────┐                │   │
│  │  │ magic pool_guid     │    │ magic pool_guid     │                │   │
│  │  │ device_guid commit_group     │    │ device_guid commit_group     │                │   │
│  │  │ pool_state gen      │    │ pool_state gen      │                │   │
│  │  │ BLAKE3-256 checksum │    │ BLAKE3-256 checksum │                │   │
│  │  └─────────────────────┘    └─────────────────────┘                │   │
│  └───────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Implementation crate map

| Crate | Role | Status |
|---|---|---|
| `tidefs-types-pool-label-core` | PoolLabelV1 type, encode/decode, BLAKE3-256 checksum, `no_std` | **Phase 1 — implemented** |
| `tidefs-local-object-store` | Pool, Device (Single, Mirror), DeviceImpl trait, PoolConfig, ClassMap, DeviceState, DeviceStats | **Core types — implemented** |
| `tidefs-local-object-store` (new) | PoolImporter, PoolExporter, DeviceManager | **Phases 2–5, 7 — deferred to wire-up** |
| `tidefs-pool-allocator` | PoolAllocator, SegmentFreeMap, per-metaslab cursors, pressure signaling | **Phase 6 — implemented** |
| `tidefs-xtask` | Integration test gates | **Phase 7 — deferred to wire-up** |

### 1.3 I/O class routing

Pool routes I/O to devices by device class:

| IoClass | Target device classes | Fallback |
|---|---|---|
| `Data` | `Data` (deterministic hash across devices) | — |
| `Metadata` | `Metadata`, `Special` | `Data` |
| `IntentLog` | `IntentLog` (write-all) | `Data` |
| `ReadCache` | `ReadCache` | `Data` |

Spare devices never participate in normal I/O routing.

---

## 2. Data structures

### 2.1 PoolLabelV1 (on-device, Phase 1 implemented)

Each device carries two label copies (L0 at offset 0, L1 at offset `capacity - 256 KiB`).
Each copy is 256 KiB, self-contained, independently verifiable via BLAKE3-256 checksum.

```rust
// tidefs-types-pool-label-core — implemented
pub const POOL_LABEL_MAGIC: [u8; 4] = *b"VBFS";
pub const POOL_LABEL_SIZE: usize = 256 * 1024;
pub const POOL_NAME_MAX: usize = 255;

pub enum PoolState { Active = 0, Exported = 1, Destroyed = 2 }

pub enum DeviceClass { Hdd = 0, Ssd = 1, Nvme = 2, LogDevice = 3, Cache = 4, Special = 5, Spare = 6 }

pub struct PoolLabelV1 {
    pub magic: [u8; 4],            // b"VBFS"
    pub version: u32,              // 1
    pub pool_guid: [u8; 16],       // UUID v4 — same across all devices in pool
    pub device_guid: [u8; 16],     // UUID v4 — unique per device
    pub pool_name: [u8; 255],      // UTF-8, NUL-padded
    pub pool_name_len: u16,        // actual byte count
    pub pool_state: PoolState,     // Active | Exported | Destroyed
    pub commit_group: u64,                  // last committed commit_group on this device
    pub label_commit_group: u64,            // commit_group when this label was last written
    pub topology_generation: u64,  // incremented on device add/remove
    pub device_count: u32,         // total devices in pool
    pub device_index: u32,         // 0-based index of this device
    pub device_class: DeviceClass, // Hdd|Ssd|Nvme|LogDevice|Cache|Special|Spare
    pub features_incompat: u64,    // bits: POOL_LABEL_V1 (bit 0)
    pub features_compat: u64,      // bits: DEVICE_CLASS_AWARE (0), SPARE_POLICY_SUPPORTED (1)
    pub features_ro_compat: u64,   // reserved (0)
    pub reserved: [u8; 16],        // padding for future fields
    pub checksum: [u8; 32],        // BLAKE3-256 over bytes 0..checksum_offset
}
```

**Key invariants**:
- `pool_guid` is identical on all devices in the same pool
- `device_guid` is unique per physical device across all pools
- `topology_generation` is incremented atomically on device add/remove; stored on every label
- L0 and L1 may differ transiently during label write (crash window); import resolves via `label_commit_group`
- `pool_state = Destroyed` is terminal; the label cannot be reused

### 2.2 Pool (runtime, implemented)

```rust
// tidefs-local-object-store/src/pool.rs — implemented
pub struct PoolConfig {
    pub name: String,
    pub root_path: PathBuf,
    pub devices: Vec<DeviceConfig>,
}

pub struct PoolProperties {
    pub ashift: u8,        // 9=512B, 12=4K (default 12)
    pub autoexpand: bool,
    pub failmode: FailMode, // Wait | Continue | Panic
}

pub enum PoolHealth { Online, Degraded, Faulted, Suspended }

pub struct PoolStats {
    pub device_count: usize, pub total_objects: usize, pub total_bytes: u64,
    pub total_read_ops: u64, pub total_write_ops: u64, pub total_delete_ops: u64,
    pub per_device: Vec<DeviceStats>, pub compression_ratio: f64,
}
```

### 2.3 Device (runtime, implemented)

```rust
// tidefs-local-object-store/src/device.rs — implemented
pub enum DeviceClass { Data, Metadata, IntentLog, ReadCache, Special, Spare }
pub enum IoClass { Data, Metadata, IntentLog, ReadCache }

pub struct DeviceConfig {
    pub path: PathBuf, pub class: DeviceClass, pub kind: DeviceKind,
    pub compression: Option<CompressionConfig>,
    pub encryption: Option<EncryptionConfig>,
}

pub enum DeviceKind {
    Single { path: PathBuf },
    Mirror { paths: Vec<PathBuf> },
}

pub enum DeviceState { Online, Degraded, Faulted, Offline, Removed }

pub trait DeviceImpl {
    fn put(&mut self, key: ObjectKey, payload: &[u8]) -> Result<StoredObject>;
    fn get(&self, key: ObjectKey) -> Result<Option<Vec<u8>>>;
    fn delete(&mut self, key: ObjectKey) -> Result<()>;
    fn stats(&self) -> DeviceStats;
    fn status(&self) -> DeviceStatus;
    fn scrub(&mut self, budget: u64) -> Result<ScrubStats>;
    fn close(self) -> Result<()>;
}
```

### 2.4 PoolImporter (new, deferred to wire-up)

```rust
// tidefs-local-object-store/src/pool_importer.rs — deferred to wire-up
pub struct ScanResult {
    pub device_path: PathBuf,
    pub label: PoolLabelV1,
    pub label_copy: LabelCopy,  // L0 | L1
}

pub struct CandidatePool {
    pub pool_guid: [u8; 16],
    pub pool_name: String,
    pub devices: Vec<ScanResult>,
    pub topology_generation: u64,  // majority vote
    pub recovery_commit_group: u64,         // max commit_group across all labels
}

pub struct ImportOptions {
    pub force: bool,                     // bypass state/version checks
    pub read_only: bool,
    pub device_map: HashMap<PathBuf, PathBuf>, // old→new path mapping
    pub recovery_commit_group: Option<u64>,       // override recovery point
}

pub struct PoolImporter {
    pub fn scan(root_dirs: &[PathBuf]) -> Result<Vec<ScanResult>>,
    pub fn group(results: Vec<ScanResult>) -> Vec<CandidatePool>,
    pub fn recover(candidate: &CandidatePool, opts: &ImportOptions) -> Result<PoolConfig>,
    pub fn open(config: PoolConfig) -> Result<Pool>,
}
```

### 2.5 PoolExporter (new, deferred to wire-up)

```rust
// tidefs-local-object-store/src/pool_exporter.rs — deferred to wire-up
pub enum ExportStatus { Success, InProgress { devices_written: usize } }

pub struct ExportOptions { pub verify: bool }

pub struct PoolExporter {
    pub fn quiesce(pool: &mut Pool) -> Result<()>,
    pub fn flush(pool: &mut Pool) -> Result<()>,
    pub fn write_labels(pool: &Pool) -> Result<ExportStatus>,
    pub fn verify(pool: &Pool) -> Result<()>,
    pub fn export(pool: &mut Pool, opts: ExportOptions) -> Result<()>,
}
```

### 2.6 DeviceManager (new, deferred to wire-up)

```rust
// tidefs-local-object-store/src/device_manager.rs — deferred to wire-up
pub enum DeviceOp { Add, Remove, Replace { replacement_path: PathBuf }, Offline, Online }

pub enum SparePolicy {
    Manual,                           // operator-activated only
    AutoReplace { cooldown_secs: u64 }, // automatic after fault
}

pub struct EvacuationCursor {         // Phase 5 — deferred to wire-up
    pub source_device_index: u32,
    pub last_key_emitted: Option<ObjectKey>,
    pub keys_remaining: u64,
    pub state: EvacState,             // Init | Running | Complete | Failed
}

pub struct DeviceManager {
    pub fn add_device(pool: &mut Pool, config: DeviceConfig) -> Result<()>,
    pub fn remove_device(pool: &mut Pool, device_index: u32) -> Result<()>,
    pub fn replace_device(pool: &mut Pool, device_index: u32, replacement: DeviceConfig) -> Result<()>,
    pub fn activate_spare(pool: &mut Pool, faulted_index: u32, policy: &SparePolicy) -> Result<()>,
    pub fn evacuate_device(pool: &mut Pool, cursor: &mut EvacuationCursor, budget: u64) -> Result<()>,
}
```

---

## 3. Algorithms

### 3.1 Pool import

```
1. SCAN — iterate root_dirs, read L0 and L1 labels from every device-like file
   - Verify magic (b"VBFS") and BLAKE3-256 checksum
   - Skip non-device files silently

2. GROUP — bucket ScanResults by pool_guid
   - Each unique pool_guid → one CandidatePool
   - For each pool, resolve topology_generation by majority vote:
       count occurrences of each value; pick the one with count > device_count/2
   - recovery_commit_group = max(commit_group) across all labels in the group

   - pool_state must be Active or Exported (unless force=true)
   - All devices must share the same topology_generation majority value
   - Device indices must be unique and within [0, device_count)
   - Label L0/L1 copies per device: prefer higher label_commit_group; if equal, prefer L0
   - Feature flags check: features_incompat must not have unknown bits set

4. RECOVER — reconcile labels:
   - If labels disagree on pool_state across devices, pick the most common
   - If any label's commit_group > recovery_commit_group, recover to that commit_group and replay intent log
   - Apply device_map for path translation (cross-system portability)

5. OPEN — construct Pool with Device from PoolConfig:
   - Set pool_state = Active on all labels (atomic commit_group commit)
   - Mark pool as owned (cluster mode: acquire pool lease via lock service)
```

### 3.2 Pool export

```
1. QUIESCE — stop accepting new writes:
   - Gate new commit_group formation (call commit_group_state.quiesce())
   - Complete in-flight I/O

2. FLUSH — drain all pending state to devices:
   - Flush all committed commit_groups (call commit_group_state.flush_all())
   - Flush/sync every byte-addressable member through its backing media handle
     (block device in production, regular-file image in development mode)

3. WRITE_LABELS atomically:
   - Set pool_state = Exported on every device
   - Set label_commit_group = current_commit_group on every label
   - Write L0 first, then L1, fsync each

4. VERIFY — read back L0/L1 from every device; confirm Exported state and checksums

Open design question: offline-only export (quiesce+flush+label) is chosen over online
export (which would require completing in-flight writes while serving new ones).
Online export is deferred to a future design.
```

### 3.3 Online device addition

```
1. OPEN commit_group — acquire a new commit_group number
2. INIT — open and validate the new byte-addressable device path
3. WRITE_LABELS — write PoolLabelV1 with:
    - device_index = current device_count
    - device_count = old + 1
    - topology_generation = old + 1
    - pool_guid, pool_name, other fields from existing pool
4. UPDATE_ALL_LABELS — rewrite labels on every existing device with:
    - device_count = new value
    - topology_generation = new value
    - label_commit_group = current commit_group
5. COMMIT commit_group — make topology change durable
6. REBUILD ClassMap — synchronous, not lazy (infrequent operation; immediate availability)
7. REGISTER — initialize SegmentFreeMap for new device, register with PoolAllocator

All label updates occur within a single commit_group commit to eliminate transient inconsistency.
```

### 3.4 Online device removal

```
1. EVACUATE — cursor-driven, budgeted data relocation:
    a. Persist EvacuationCursor at (device_index, last_key_emitted)
    b. For each budgeted tick: scan remaining objects on source, relocate to
       target devices via PoolAllocator, emit relocated-key tombstones on source
    c. Track refcounts: an object may share extents via snapshots/dedup;
       only relocate when source holds the exclusive last reference
    d. On crash: resume from cursor; EvacuationCursor is idempotent-safe

2. REFCOUNT_GATE — after evacuation completes, verify no live objects remain
   on source device (refcount check)

3. LABEL_UPDATE — single-commit_group batch:
    - Set DeviceState = Removed on source device label
    - Update device_count and topology_generation on all remaining devices
    - Commit commit_group

4. DEREGISTER — remove device's SegmentFreeMap from PoolAllocator
5. CLOSE — close the source device; regular-file development images may be
   removed by explicit operator/test cleanup, but pool members are not
   directory-backed devices
```

### 3.5 Online device replacement (mirror case)

```
1. ADD replacement device via §3.3 (joins as new mirror member of existing device)
2. REBUILD — copy all data from healthy members to replacement (resilver semantics)
3. REMOVE faulted/old member from mirror set
4. UPDATE labels to reflect new topology
```

### 3.6 Hot-spare activation

```
1. DETECT fault on a data-bearing device:
   - I/O error count exceeds threshold (configurable, default 5 errors in 60s)
   - Transition: ONLINE → DEGRADED → FAULTED

2. SPARE_POLICY check:
   - Manual: emit observability event, wait for operator trigger
   - AutoReplace: after cooldown_secs, find a Spare-class device matching the
     faulted device's DeviceClass; if found, begin activation

3. ACTIVATE:
   - Change spare label: DeviceClass.Spare → faulted device's DeviceClass
   - Initiate replace_device() (§3.5) with the spare as replacement
   - Rebuild completes; topology_generation incremented

4. OBSERVABILITY: emit DeviceEvent::SpareActivated with old/new device_guid
```

### 3.7 Device failure state machine

```
   ┌──────────┐   I/O error threshold met   ┌──────────────┐
   │  ONLINE  │ ──────────────────────────▶  │  DEGRADED   │
   └────┬─────┘                              └──────┬───────┘
        │                                          │
        │  admin offline cmd               further errors /
        ▼                                  all members lost
   ┌──────────┐                              │
   │  OFFLINE │ ◀────────────────────────────┘
   └──────────┘                              ▼
        │                              ┌──────────┐
        │  admin online cmd            │  FAULTED  │
        ▼                              └─────┬────┘
   ┌──────────┐                              │
   │  ONLINE  │              admin remove cmd│
   └──────────┘                              ▼
        │                              ┌──────────┐
        └──────────────────────────────│  REMOVED  │ (terminal)
                                      └──────────┘

State semantics:
- ONLINE: fully operational, serving reads and writes
- DEGRADED: at least one mirror member offline/erroring; writes still possible
  (all members), reads served from healthy members
- FAULTED: all members unreachable; device cannot serve I/O; data unavailable
  unless redundancy exists at pool level
- OFFLINE: administratively taken down; not auto-recovered; operator bring-up
- REMOVED: permanently evicted from pool; label still present for provenance
```

---

## 4. 7-Phase implementation plan

### Phase 1: PoolLabelV1 on-device format — **IMPLEMENTED**
- Crate: `tidefs-types-pool-label-core`
- Deliverables: `PoolLabelV1` struct, `PoolState`/`DeviceClass` enums,
  BLAKE3-256 checksum, `encode_label`/`decode_label`/`verify_label_checksum`/
  `seal_label`, `no_std` compatible
- Status: merged to `master`

### Phase 2: PoolImporter — **deferred to wire-up**
- Crate: `tidefs-local-object-store/src/pool_importer.rs`
- Key algorithm: majority-vote `topology_generation`, L0/L1 label resolution,
  `device_map` path translation for cross-system portability

### Phase 3: PoolExporter — **deferred to wire-up**
- Crate: `tidefs-local-object-store/src/pool_exporter.rs`
- Deliverables: `quiesce()`, `flush()`, `write_labels()`, `verify()`, `export()`
- Key invariant: atomic label write (L0→L1, fsync each); crash-safe via
  two-copy redundancy

### Phase 4: DeviceManager — device add/remove/replace — **deferred to wire-up**
- Crate: `tidefs-local-object-store/src/device_manager.rs`
- Deliverables: `add_device()`, `remove_device()`, `replace_device()`
- Key algorithm: single-commit_group batch label update for topology changes;
  synchronous ClassMap rebuild

### Phase 5: Evacuation engine integration — **deferred to wire-up**
- Crate: `tidefs-local-object-store/src/evacuation.rs`
- Deliverables: `EvacuationCursor` state machine, `evacuate_device()`
- Depends on: #1239/#1229/#1241 (data evacuation engine), #1237 (budgeted scheduling)
- Key contract: cursor-driven, budgeted-per-tick, idempotent on restart,
  refcount-gated before label removal

### Phase 6: Per-metaslab allocator cursors — **IMPLEMENTED**
- Crate: `tidefs-pool-allocator`
- Deliverables: `PoolAllocator`, `SegmentFreeMap`, `MetaslabAllocStats`,
  per-metaslab cursors, pressure signaling, ENOSPC propagation
- Status: merged to `master`; single-threaded allocation path;
  per-metaslab data structures ready for future parallelism

### Phase 7: Integration gates and xtask — **deferred to wire-up**
- Crate: `tidefs-xtask`
- Deliverables: `check-pool-import-export` (export/import roundtrip),
  `check-device-topology` (generation majority, device_count consistency),
  `check-label-corruption` (inject corruption, verify detection)
- Additionally: cluster-aware pool import with lease acquisition
  (#1283, #1248); STATUS.md and FEATURE_MATRIX.md updates

### Per-metaslab parallelism deferral

Per-metaslab parallelism is explicitly **deferred** to the metadata engine
parallelism design (#1278). Phase 6 already provides per-metaslab data
structures (separate `SegmentFreeMap` and allocation cursors per metaslab),
but the allocation path is single-threaded. When per-metaslab parallelism
lands, the pool device management surfaces (add, remove, replace) remain
unchanged — only the allocator's internal concurrency model changes.

**Rationale**: Correctness-first. Sequential device management eliminates
concurrency bugs in topology transitions. The parallel data structures are
already in place; wiring them up to a thread pool is a pure performance
optimization that does not change any public API.

---

## 5. Tradeoffs

| Decision | Alternative | Rationale |
|---|---|---|
| Fixed 255-byte pool name | Variable-length encoding | Simpler checksum boundary; <0.1% of 256 KiB label |
| BLAKE3-256 checksum | SHA-256, BLAKE2 | 3× faster; tree-hashing for future incremental label updates |
| Directory-scan import | Config-file cache | Labels are source of truth; cache is perf optimization, deferred |
| Majority vote for topology_generation | Strict consistency | Handles partial-label-write crash; force_import escape hatch |
| Offline-only export | Online export | Simpler quiesce model; online export deferred to future design |
| Two label copies (L0/L1) | Single copy | Crash resilience: import resolves split state via label_commit_group |
| Single-commit_group batch for device add | Multi-commit_group incremental | Eliminates transient inconsistency window |
| Synchronous ClassMap rebuild | Lazy rebuild | Infrequent operator action; immediate availability > latency |
| Cursor-driven evacuation | Bulk evacuation | Resumable, budgeted, production-safe for large devices |
| Refcount gate for removal | Scan-and-move | Correct for shared extents (snapshots, dedup) |
| Error-rate threshold for faults | Single-error fault | Avoids transient faults; threshold tunable |
| Built-in SparePolicy | External ZED-like daemon | Eliminates external dependency; observability events enable external override |
| Sequential device mgmt (deferred parallelism) | Immediate parallelism | Correctness-first; per-metaslab data structures already in place |
| PoolLabelV1 `no_std` | std-only | Enables bootloader/initramfs label reading |

---

## 6. Integration contracts

### 6.1 CommitGroup state machine (#1267)
- **Import**: `PoolImporter` calls `commit_group_state.open_at(commit_group)` with recovery commit_group
- **Export**: `PoolExporter` calls `commit_group_state.quiesce()` then `commit_group_state.flush_all()`
- **Add**: `DeviceManager` opens new commit_group, stages labels, commits
- **Remove**: Evacuation runs across commit_groups; final label update is single-commit_group commit

### 6.2 Data evacuation engine (#1239, #1229, #1241)
- Phase 5 uses the cursor-driven evacuation engine for `EvacuationCursor`
  state machine, budgeted work ticks, and locator table traversal
- The evacuation engine is independent; Phase 5 provides pool-level orchestration

### 6.3 Spacemap allocator (#1189, #1694)
- **Add**: Initialize `SegmentFreeMap` for new device, register with `PoolAllocator`
- **Remove**: Deregister device's free map after evacuation completes

### 6.4 Cluster membership (#1283) and lock service (#1248)
- **Phase 7 deferred**: Cluster pool import requires pool lease acquisition
  and cluster membership registration
- Write-side lease check before commit_group commit; fencing on lease expiry

### 6.5 Serial write surface contracts
- `crates/tidefs-local-filesystem/src/lib.rs` — serial write surface
- `crates/tidefs-local-object-store/src/lib.rs` — serial write surface
- Only one active issue may edit each at a time

---


### 7.1 Unit tests (per phase)
- `PoolLabelV1` encode/decode roundtrip with valid and invalid inputs
- Checksum verification: correct checksum passes, corrupted checksum fails
- Label L0/L1 redundancy: read from either copy, prefer newer `label_commit_group`
- `DeviceState` transition logic: valid transitions succeed, invalid ones panic/error
- `DeviceClass` → `IoClass` routing: correct device index selection

### 7.2 Integration tests
- **Export/import roundtrip**: create pool, write data, export, import on
  different paths, verify all data checksums match
- **Export atomicity**: simulate crash during label write; verify import detects
  split state and resolves correctly
- **Device add**: create pool with 1 device, add second, verify `device_count`
  and `topology_generation` consistent, verify data on new device readable
- **Device remove**: create pool with 2 devices, evacuate one, remove it,
  verify remaining device labels updated, verify all data accessible
- **Device replace (mirror)**: create mirror pool, replace a member, verify
  rebuild completes, verify data integrity
- **Hot-spare**: create pool with spare, fault a device, verify auto-activation,
  verify rebuild completes
- **Failure handling**: inject I/O errors, verify state transitions
  (ONLINE → DEGRADED → FAULTED), verify observability events emitted
- **Cross-system portability**: export pool, move devices to different paths,
  import with new paths, verify data integrity

### 7.3 xtask gates (Phase 7)
- `tidefs-xtask check-pool-import-export`: full integration test suite
- `tidefs-xtask check-device-topology`: topology_generation majority vote,
  device_count consistency, device_index uniqueness
- `tidefs-xtask check-label-corruption`: inject label corruption, verify
  import detects and reports it

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Label write atomicity violation on crash | Medium | High | Two-copy redundancy, import-time state resolution, `label_commit_group` disambiguation |
| Split topology generation after partial add/remove | Low | Medium | Majority-vote rule on import, force-import escape hatch |
| Evacuation cursor fails mid-operation | Medium | Medium | Persistent cursor state, resumable after restart, budgeted per tick |
| Cluster lease expiry during active I/O | Low | High | Fencing on expiry, write-side lease check before commit_group commit |
| Label format version mismatch across cluster | Low | Medium | Feature flag bits, version negotiation, read-only fallback |
| Device class forward-compatibility gap | Low | Low | `Unknown(u8)` variant, treated as generic data device |

---

## 9. Non-claims (explicit boundaries)

- This design does not include the data evacuation engine implementation — #1239, #1229, #1241
- This design does not cover erasure coding redundancy or rebuild algorithms — #1249
- This design does not specify the ADMIN service protocol or replicated commit_group commit — #1243 and cluster design suite
- This design does not change the local filesystem's single-device I/O path; multi-device allocation and I/O scheduling are deferred
- This design does not include pool geometry conversion (mirror ↔ erasure coding) — #1275
- This design does not implement per-metaslab parallelism — #1278

---

## 10. ZFS / Ceph Prior-Art Comparison

This comparison records design inputs and planned behavior. The TideFS column
is not a current capability, availability, cost, durability, or better-than-
incumbent claim; any such product-facing statement must use #875 claim ids and
#928/#930 comparator evidence.

| Dimension | ZFS prior art | Ceph prior art | TideFS design target |
|---|---|---|---|
| Label format | 256 KiB device_label, 4 copies | None (monitor cluster) | 256 KiB PoolLabelV1, 2 copies, BLAKE3-256 |
| Import mechanism | `zpool import -a` scans all devices | OSDs connect to monitors | Label-driven scan + pool_guid grouping; portable |
| Export | Offline: unmount datasets, write labels | N/A (no pool export) | Offline: quiesce, flush, atomic label write |
| Device addition | `zpool add` | `ceph osd create` | Online: label + commit_group-consistent batch update |
| Device removal | Post-0.8.0, mirror-only | `ceph osd out` + rebalance | Online: evacuation + refcount gate + label update |
| Device replacement | `zpool replace` (manual) | `ceph osd destroy` + new OSD | Online: add-new + rebuild + remove-old composite |
| Hot-spare | External `zed` scripting | CRUSH map `device class` | Built-in `SparePolicy` with auto-activation |
| Failure handling | zed event → `device state` | Monitor marks OSD down | I/O error → state machine → observability event |
| Cluster integration | None (single-node) | Native (monitor cluster) | Hybrid: standalone or cluster mode; pool lease |
| Cross-system portability | Yes (label-driven) | No (monitor-bound) | Yes (label-driven, device_guid identity) |

---

## 11. Phase completion criteria

Each phase is complete when:

1. Source changes are merged to `master` in the target crate(s)
2. Unit tests pass for the phase's data structures and algorithms
3. Integration tests pass for applicable scenarios
4. xtask gate (Phase 7) passes for the cumulative set of implemented phases
5. Forgejo issue is closed with commit SHA, commands run, result, and residual risk
6. `docs/STATUS.md` is updated with the phase completion entry
7. `docs/FEATURE_MATRIX.md` is updated when capability state changes

---

## 12. References

- CommitGroup state machine: [#1267](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1267)
- Data evacuation: [#1239](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1239)
- Budgeted scheduling: [#1237](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1237)
- Cluster membership: [#1283](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1283)
- Distributed lock service: [#1248](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1248)
- Metadata engine parallelism: [#1278](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1278)
- Pool allocator (G2+ multi-device): [#1694](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1694)
- Spacemap allocator design: [#1189](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1189)
- ADMIN service: [#1243](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1243)
- Pool geometry conversion: [#1275](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1275)
- Erasure coding: [#1249](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1249)
