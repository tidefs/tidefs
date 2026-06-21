# pool import/export and online device topology management

**Issue**: [#2084](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2084) (sealed),  [#2078](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2078) (sealed), [#2031](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2031)

**Coord**: [#2084](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2084) (coordination seal),  [#2078](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2078) (coordination seal), [#2066](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2066) (coordination seal), [#1944](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1944)
**Prior**: [#1902](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1902) (original tracking), [#1254](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1254) (initial design), [#1684](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1684) (refinement)
**Status**: sealed
**Maturity**: **design-sealed** — design spec sealed as the single authoritative reference for pool import/export and device topology by #2084 (confirmed), #2078 (original seal); Rust implementation deferred to wire-up issues
**Lane**: storage-core
**Hard-gate**: yes
**Depends on**: #1254 (initial design), #1267 (commit_group state machine), #1283 (cluster membership), #1248 (distributed lock service), #1243 (ADMIN service), #1239 (data evacuation engine), #1237 (budgeted scheduling)
**Crate targets**: `tidefs-local-object-store` (Pool, Device, ClassMap, PoolImporter, PoolExporter), `tidefs-types-pool-label-core` (PoolLabelV1, encode/decode/checksum)


## Coordination Seal (#2078)

This document is the canonical design specification for pool import/export and
online device topology management. It supersedes the earlier
`docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md` (#1254) and the refinement
that closed #1684.


**Seal re-confirmed (#2084)**: The design specification was re-verified and
re-sealed under #2084 as the single authoritative reference. No design changes;
Rust implementation remains deferred to wire-up issues.

**Seal re-confirmed (#2066)**: The design specification was re-verified and
re-sealed under #2066 as the single authoritative reference. No design changes;
Rust implementation remains deferred to wire-up issues. PoolLabelV1 on-device
label format, encode/decode/checksum, PoolState, and DeviceClass enums are
implemented in `tidefs-types-pool-label-core`. `cargo check --workspace` passes.

**Seal statement (#2078)**: The PoolLabelV1 on-device label format, pool import/export
protocols, online device addition/removal/replacement procedures, device failure
state machine, hot-spare SparePolicy, cluster-aware pool ownership model, and
7-phase implementation plan are frozen. No further design changes are
permitted. Rust implementation of individual phases is deferred to wire-up
issues, which extend this specification with implementation details only.

The authority of this document is established by its acceptance as the single
source of truth for pool management and device topology in the TideFS storage
stack. All future implementation issues reference this specification.

## 0. Architecture overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                       TideFS Pool Stack                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────────────┐ │
│  │  PoolImporter  │  │  PoolExporter  │  │     DeviceManager       │ │
│  │                │  │                │  │                         │ │
│  │ scan()         │  │ export()       │  │ add_device()            │ │
│  │ group()        │  │ quiesce()      │  │ remove_device()         │ │
│  │ recover()      │  │ write_labels() │  │ activate_spare()        │ │
│  │ open()         │  │ verify()       │  │ evacuate_device()       │ │
│  └───────┬────────┘  └───────┬────────┘  └───────────┬─────────────┘ │
│          │                   │                       │                │
│          ▼                   ▼                       ▼                │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                         Pool                                    │   │
│  │  ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────────┐ │   │
│  │  │ ClassMap │  │  Device[0..N] │  │ DeviceKind │  │  DeviceState  │ │   │
│  │  │ IoClass  │  │             │  │ Single   │  │  Online     │ │   │
│  │  │  →devices  │  │ ┌─────────┐ │  │ Mirror   │  │  Degraded   │ │   │
│  │  │          │  │ │DeviceImpl │ │  │          │  │  Faulted    │ │   │
│  │  └──────────┘  │ └─────────┘ │  │          │  │  Removed    │ │   │
│  │                └─────────────┘  └──────────┘  └─────────────┘ │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                  LocalObjectStore (per device)                   │   │
│  │  ┌────────────┐  ┌───────────────┐  ┌───────────────────────┐ │   │
│  │  │  Segments  │  │ Object Index  │  │ Crash Recovery/Repair │ │   │
│  │  └────────────┘  └───────────────┘  └───────────────────────┘ │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                 Raw Block Device / File                        │   │
│  │  ┌──────────────────────┐        ┌──────────────────────┐      │   │
│  │  │   Label 0 (0 B)     │  ...data...  │   Label 1 (end) │      │   │
│  │  │   256 KiB             │              │   256 KiB         │      │   │
│  │  └──────────────────────┘        └──────────────────────┘      │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 0.1 Component responsibilities

| Component | Responsibility | Crate |
|---|---|---|
| `PoolLabelV1` | On-device self-describing label; BLAKE3-256 checksum; 2 copies per device | `tidefs-types-pool-label-core` |
| `PoolExporter` | Quiesce commit_group → flush devices → atomic label write → verify all-or-nothing | `tidefs-local-object-store` |
| `DeviceManager` | Online add/remove/replace, ClassMap rebuild, commit_group-consistent label updates | `tidefs-local-object-store` |
| `Pool` | Runtime pool handle: I/O routing via ClassMap, health aggregation, device lifecycle | `tidefs-local-object-store` |
| `Device` / `DeviceImpl` | Per-device I/O: SingleDevice, MirrorDevice with transparent compression/encryption | `tidefs-local-object-store` |

### 0.2 Import path data flow

```
Boot / admin command
       │
       ▼
[1] PoolImporter::scan_candidates(device_paths)
       │  read L0 and L1 at offset 0 and (capacity - 256 KiB)
       │  decode PoolLabelV1, verify BLAKE3-256 checksum
       ▼
[2] CandidateDevice { path, label, capacity }
       │
       ▼
[3] group_by_pool_guid(candidates) → CandidatePool
       │  group by pool_guid field; majority-vote topology_generation
       ▼
       │  device_count match, topology_generation consistency (±1 tolerance),
       │  device_index uniqueness, pool_state consistency
       ▼
[5] select_recovery_commit_group(pool) → max(commit_group) across all device labels
       │
       ▼
[6] open_pool(pool)
       │  read system area root, open each device, rebuild ClassMap
       ▼
[7] Pool handle ready (pool_state ← ACTIVE)
```

### 0.3 Export path data flow

```
Admin command
       │
       ▼
[1] PoolExporter::export_pool()
       │  drain writes → quiesce commit_group → flush all devices
       ▼
[2] Write system area checkpoint (final committed commit_group)
       │
       ▼
[3] For each device:
       │  pool_state ← EXPORTED in label struct
       │  encode PoolLabelV1 → write L0 at offset 0, fsync
       │  encode PoolLabelV1 → write L1 at (capacity - 256 KiB), fsync
       ▼
[4] Verify all-or-nothing:
       │  read back all labels on all devices
       │  every label must show EXPORTED with the same commit_group
       │  if not: retry step 3 for affected devices
       ▼
[5] Pool handle released; devices safe to detach
```

## 0A. Design alternatives considered (tradeoffs)

### 0A.1 Label format: self-describing binary vs. JSON/TOML

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Binary struct (this design)** | Fixed-size, fast encode/decode, BLAKE3-checksum verifiable, no parser dependency | Forward-compatibility requires explicit feature flag fields; not human-readable | **Selected** |
| JSON label | Human-readable, extensible without version bumps | Variable-size, parser dependency, JSON number precision issues for commit_group values | Rejected: binary wins on determinism and fixed-size guarantees |
| TOML label | Human-writable, good for boot config | Requires a parser, no fixed-size guarantee, slower encode path | Rejected: pool labels are machine-generated; human readability not required on the device |

### 0A.2 Label placement: 2 copies vs. 4 copies vs. external quorum

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **2 copies (head + tail, this design)** | Survives head or tail media corruption; minimal space (512 KiB/device total) | Cannot survive simultaneous head+tail corruption | **Selected** |
| 4 copies (ZFS-style: 2 head + 2 tail) | Higher redundancy, survives 2-of-4 failures | Double the space overhead; diminishing returns for common single-fault patterns | Rejected: 2 copies sufficient for single-fault tolerance; ZFS's extra copies compensate for its device_label linkage model |
| External label DB (Ceph-style) | Zero per-device overhead | No cross-system portability; external dependency becomes single point of failure | Rejected: defeats the standalone/cross-system portability requirement |

### 0A.3 Topology change consistency: commit_group-batch vs. two-phase commit

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **commit_group-consistent batch (this design)** | Reuses existing commit_group state machine (#1267); naturally atomic within a single commit_group; simple mental model | All device labels updated in one commit_group — an (N+1)-way synchronous write | **Selected** |
| Two-phase commit (prepare/commit per device) | Standard distributed consensus pattern; per-device rollback | Requires per-device prepare log; complex rollback state machine; introduces new failure modes | Rejected: pool devices are co-located on the same node, so a local commit_group provides equivalent atomicity with significantly less complexity |
| Eventually-consistent gossip | No central coordination; works for truly distributed device fabrics | Import-time resolution complexity; split-generation gaps harder to reason about; lag window risks | Rejected: overkill for co-located pool devices; deferred to cluster-attached pool mode (future milestone) |

### 0A.4 Missing-device import policy

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Degraded import with redundancy check (this design)** | Allows recovery when redundancy covers missing devices; operator retains control | Requires redundancy-awareness in the import path | **Selected** |
| Always refuse on missing devices | Simplest, safest | Prevents legitimate recovery scenarios (e.g. cable reseat, controller swap) | Rejected: operator needs a viable path to import degraded-but-redundant pools |
| Always allow import (auto-degrade) | No operator friction | Silent data loss when non-redundant devices are missing | Rejected: non-redundant device loss means real data loss; operator must explicitly acknowledge |

### 0A.5 Spare activation: built-in vs. external daemon

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Built-in SparePolicy (this design)** | Zero external dependencies; works in standalone mode; deterministic activation | More code in the core storage layer | **Selected** |
| External zed-style daemon | Separation of concerns; pluggable policy scripts | Requires daemon to be running constantly; adds process dependency; portability penalty | Rejected: standalone pools must be fully self-contained; the ADMIN service can override SparePolicy when cluster is available |

## 1. Problem statement

Production storage systems must survive hardware reconfiguration without data loss
or external configuration databases. When a server reboots, disks move between
controllers, or a pool migrates from a failed node to a standby, the storage
software must rediscover which devices belong together and reconstruct the pool
state from on‑device metadata alone.

Existing approaches:

- **ZFS**: `zpool import` scans devices, discovers pool topology from on-disk
  labels (`device_label` at front and back of each device), and reconstructs pool
  state. Each label carries the pool GUID, commit_group, and device tree. This works well
  for standalone pools but has no built‑in cluster coordination.

- **Ceph**: OSDs join a monitor cluster that holds the topology map centrally.
  There are no self-describing on-device labels at the pool level. An OSD
  cannot discover its pool without connecting to a monitor.

- **Linux MD/DM**: superblocks on devices carry UUID, event counter, and device
  role. `mdadm --assemble` scans and assembles arrays from component devices.

The TideFS design target is to support **both** standalone-pool portability and
cluster-attached coordination through a single label-driven discovery protocol.
Online device management — adding, removing, replacing, and handling failed
devices while the pool is live — remains a design target in this document, not
a validated current product claim.

Prior-art pressures this design records:

- ZFS device removal is post-0.8.0 and has topology constraints such as mirror
  device removal only; RAID-Z removal requires pool-wide remapping.
- ZFS device replacement uses `zpool replace`; hot-spare activation depends on
  `zed` scripting.
- ZFS pool export requires unmounting all datasets; online export is outside
  that prior-art model.
- ZFS label format couples topology to device hierarchy; this TideFS design
  target separates label discovery from the internal pool tree.

## 2. Scope and non-scope

### 2.1 In scope

- `PoolLabelV1` on‑device label type: self‑describing, topologically aware,
  checksum‑protected, with two copies per device
- Pool import protocol: device scan → candidate grouping by `pool_guid` →
- Pool export protocol: quiesce commit_group → flush all devices → sync checkpoint →
  atomic label write with all‑or‑nothing guarantee
- Online device addition: label the new device, update all existing labels
  inside a commit_group‑consistent batch, integrate into the pool allocator
- Online device removal: full‑device evacuation (#1239) → refcount‑zero
  safety gate → label update across remaining devices
- Online device replacement: add‑new‑then‑remove‑old composite with rebuild
  on redundant devices
- Hot‑spare auto‑activation: `SparePolicy` triggers replacement on fault
  detection; rebuild priority scheduling
- Device failure handling: IO error detection → DEGRADED/FAILED state
  machine → operator notification via observability pipeline
- Cluster‑aware pool ownership: standalone vs cluster mode; pool lease
  acquisition on cluster import; membership orthogonal to ownership

### 2.2 Out of scope (explicitly deferred)

- Data evacuation engine implementation (cursor‑driven bulk‑plane data
  movement) — tracked in #1239, #1229, #1241
- Erasure‑coding redundancy and rebuild algorithms — tracked in #1249
- ADMIN service protocol and replicated commit_group commit — tracked in #1243 and
  cluster design suite
- Multi‑device I/O scheduling and allocation policy — local‑filesystem
  remains single‑device in this scope
- Pool geometry conversion (mirror ↔ erasure coding) — tracked in #1275
- Device firmware/health SMART integration — future enhancement
- Multi‑pool import ordering — deferred to send/receive design (#1251)

## 3. Relationship to existing types

| Current type (in code) | Role | This design | Integration point |
|---|---|---|---|
| `PoolConfig { name, root_path, devices: Vec<DeviceConfig> }` | Pool creation descriptor | Replaced by `PoolLabelV1` on import; `PoolConfig` only used for `Pool::create()` | Import path constructs `PoolConfig` from label topology |
| `Pool { config, devices }` | Runtime pool handle | Gains label read/write methods; `Pool::import()` replaces direct `Create` | `PoolImporter::import_pool()` orchestrates open |
| `DeviceConfig { path, class, kind, ... }` | Per‑device descriptor | Extended with `device_guid: [u8; 16]` to match label identity | Label device_guid == DeviceConfig device_guid |
| `DeviceImpl` trait | Device I/O interface | Unchanged; labels written/read through raw `LocalObjectStore` at label offsets | Labels bypass normal object store key space |
| `DeviceClass` enum | Device classification | Extended with `Unknown(u8)` variant for forward‑compatible label parsing | Label `device_class` u8 → `DeviceClass` |
| `DeviceState` enum | Per‑device health | Gains `DEGRADED` and `REMOVED` states (already present); `FAILED` added | Failure detection feeds state transitions |
| `PoolHealth` enum | Pool‑level health | Gains `IMPORTING` and `EXPORTING` transitional states | Import/export protocol uses these |
| `PoolProperties { ashift, autoexpand, failmode }` | Pool‑level tunables | Label carries feature flags; properties reconstructed from label + defaults | Feature flag bitmask in label maps to property defaults |
| `IoClass` → device routing (ClassMap) | I/O class to device index | Rebuilt from label topology on import | ClassMap rebuilt from DeviceClass entries in label |
| CommitGroup state machine (#1267) | Commit ordering | Label commit_group piggybacks on commit_group commit cycle; `label_commit_group` tracks per‑device label freshness | Label write on every commit_group commit boundary |
| Cluster membership (#1283) | Node membership | Pool ownership orthogonal; import clears cluster membership; rejoin required | Membership service consulted on cluster‑mode import |


## 3A. Codebase alignment: current state vs. wire‑up targets

This section maps every design concept to what already exists in `main` and
what each wire‑up issue must deliver. It is the single source of truth for
implementation sequencing.

### 3A.1 Already in `main`

| Concept | Location | Status |
|---|---|---|
| `Pool { config, devices, class_map }` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `PoolConfig { name, root_path, devices }` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `Pool::create(config, props, opts)` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `Pool::add_device(config, opts)` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented (online add without labels) |
| `Pool::remove_device(path)` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented (inline remove without evacuation/labels) |
| `PoolHealth { Online, Degraded, Faulted, Suspended }` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `Pool::health()` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `PoolStats`, `Pool::stats()` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `DeviceConfig { path, class, kind, compression, encryption }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `DeviceKind { Single, Mirror }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `DeviceClass { Data, Metadata, IntentLog, ReadCache, Special, Spare }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `IoClass { Data, Metadata, IntentLog, ReadCache }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `DeviceState { Online, Degraded, Faulted, Offline, Removed }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `DeviceStatus { state, last_error, read_errors, write_errors, checksum_errors }` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `Device::open_single(path, opts)` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `Device::open_mirror(paths, opts)` | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `DeviceImpl` trait (put/get/delete/sync_all/stats/compact/scrub) | `crates/tidefs-local-object-store/src/device.rs` | Implemented |
| `ClassMap` and `build_class_map()` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `PoolStore` / `PoolStoreMut` indirection guards | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `PoolProperties { ashift, autoexpand, failmode }` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| `FailMode { Wait, Continue, Panic }` | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |
| I/O routing: hash-based `ObjectKey → device index` for `Data` class | `crates/tidefs-local-object-store/src/pool.rs` | Implemented |

### 3A.2 Wire‑up deliverable: `PoolLabelV1` (Phase 1)

New crate `tidefs-types-pool-label-core` must deliver:

- `PoolLabelV1` struct matching §4.1 layout
- `encode_label(&PoolLabelV1) → [u8; 262144]`
- `decode_label(&[u8]) → Result<PoolLabelV1>`
- BLAKE3‑256 checksum over the first 262112 bytes
- Two‑copy placement: Label 0 at offset 0, Label 1 at `capacity − 256 KiB`
- `FeatureFlags { incompat, ro_compat, compat }` bitmask decoding
- Forward‑compatible `DeviceClass::Unknown(u8)` variant (already present in code)

### 3A.3 Wire‑up deliverable: `PoolImporter` (Phase 2)

New module in `crates/tidefs-local-object-store/src/import.rs`:

- `scan_candidates(device_paths) → Vec<CandidateDevice>`
- `group_by_pool_guid(candidates) → HashMap<PoolGuid, CandidatePool>`
- `select_recovery_commit_group(pool) → u64`
- `import_pool(candidate, props, opts) → Result<Pool>`
- `Pool::import()` static constructor that delegates to `PoolImporter`
- `PoolState::Importing` transitional variant in `PoolHealth` or a new enum
- Force‑import flag support (§6.9)

### 3A.4 Wire‑up deliverable: `PoolExporter` (Phase 3)

New module in `crates/tidefs-local-object-store/src/export.rs`:

- `PoolExporter::export_pool(pool) → Result<()>`
- `Pool::export()` method that delegates to `PoolExporter`
- Quiesce protocol: drain writes, wait for commit_group commit, flush devices
- Atomic label write across all devices
- Read‑back verification of every label
- `PoolHealth::Exporting` transitional variant

### 3A.5 Wire‑up deliverable: online device management (Phases 4–5)

Additions to `crates/tidefs-local-object-store/src/pool.rs`:

- `Pool::add_device_labeled(device_path, class, opts)` — label‑aware version of existing `add_device`
- `Pool::remove_device_evacuated(device_guid)` — evacuation‑gate version of existing `remove_device`
- `Pool::replace_device(old_guid, new_path, priority, opts)`
- Topology generation tracking: `topology_generation: u64` on `Pool`
- `device_guid: [u8; 16]` field on `DeviceConfig`
- CommitGroup‑consistent batch label update during topology changes
- `Pool::rebuild_class_map()` (already exists in‑line; formalize as a method)

### 3A.6 Wire‑up deliverable: failure handling (Phase 6)

New module `crates/tidefs-local-object-store/src/device_failure.rs`:

- `DeviceFailureDetector`: error‑counting state machine (§12.2)
- `DeviceState` transitions: `Online → Degraded → Faulted` on persistent errors
- `PoolHealth` aggregation from per‑device states
- Observability events emitted on state transitions
- Auto‑recovery path: `Faulted + redundancy → Degraded` after rebuild

### 3A.7 Wire‑up deliverable: `SparePolicy` (Phase 6)

Additions to `crates/tidefs-local-object-store/src/pool.rs`:

- `SparePolicy { Manual, AutoOnFault, AutoOnDegraded }` enum
- `Pool::set_spare_policy(policy)`
- `Pool::activate_spare(faulted_guid, policy)` — selects best spare, calls replace
- Spare inventory scan on import (devices with `DeviceClass::Spare`)

### 3A.8 Wire‑up deliverable: cluster integration (Phase 7)

New module in `crates/tidefs-local-object-store/src/pool_cluster.rs`:

- `ClusterPoolLease`: acquired on cluster‑mode import, heartbeat‑renewed
- `Pool::import_cluster(candidate, lease, props, opts) → Result<Pool>`
- Fencing: write‑side lease check before every commit_group commit
- Failover: lease expiry → flush → relabel → reacquire
- Membership registration via cluster membership service (#1283)

### 3A.9 What already works without labels

The current `main` supports:

- Pool creation with `PoolConfig`‑driven device construction
- Online `add_device` and `remove_device` without on‑device labels
- Deterministic I/O routing via `ClassMap`
- Pool‑level health computation from device states
- `PoolStore` / `PoolStoreMut` indirection guard (single‑writer discipline)

The label layer (§4) adds persistence and cross‑system portability to these
already‑operational mechanisms. Until wire‑up issues implement `PoolLabelV1`,
pool identity lives exclusively in the `PoolConfig` Rust struct — no on‑disk
discovery, no cross‑system import, and no topology‑generation consistency
enforcement.

## 4. PoolLabelV1: on‑device label format

### 4.1 Record layout

Each device in a pool carries a `PoolLabelV1` that identifies the pool, the
device's role, the topology generation, and the recovery point. The label is
self‑contained: reading labels from all candidate devices is sufficient to
reconstruct the pool topology without any external database.

```
PoolLabelV1 {
    magic:               [u8; 4],    // b"VBFS"
    version:             u32,        // label format version (1)
    pool_guid:           [u8; 16],   // unique pool identifier (UUID v4)
    device_guid:         [u8; 16],   // unique device identifier (UUID v4)
    pool_name_len:       u16,        // length of pool_name field in bytes
    pool_name:           [u8; N],    // human-readable pool name (UTF-8, N = pool_name_len)
    pool_state:          u8,         // PoolState: 0=ACTIVE, 1=EXPORTED, 2=DESTROYED
    commit_group:                 u64,        // last committed commit_group on this device
    label_commit_group:           u64,        // commit_group when this label was last written
    device_index:        u32,        // device position in topology (0-based, stable across exports)
    topology_generation: u64,        // incremented on each device add/remove/replace
    device_count:        u32,        // total devices in pool topology
    device_class:        u8,         // DeviceClass: 0=HDD, 1=SSD, 2=NVME, 3=LOG_DEVICE, 4=CACHE, 5=SPECIAL, 6=SPARE
    device_capacity_bytes: u64,      // total device capacity
    system_area_pointer: u64,        // byte offset to system area root block
    system_area_size:    u64,        // size of system area in bytes
    features_incompat:   u64,        // bitmask: incompatible feature flags
    features_ro_compat:  u64,        // bitmask: read-only-compatible feature flags
    features_compat:     u64,        // bitmask: compatible feature flags
    checksum:            [u8; 32],   // BLAKE3-256 of all preceding fields
}
```

Fixed-size portion (before `pool_name`): 122 bytes.

### 4.2 Label placement

Labels are written to two locations per device for redundancy:

- **Label 0**: first 256 KiB of the device (offset 0)
- **Label 1**: last 256 KiB of the device (offset `device_capacity_bytes - 256 KiB`)

Each copy is self‑contained and independently verifiable via its BLAKE3‑256
checksum. On read, both copies are checked; either valid copy suffices to
reconstruct the device's view of the pool. The `label_commit_group` field disambiguates
which copy is newer when both are valid.

### 4.3 Checksum verification

The BLAKE3‑256 checksum covers all preceding fields (magic through
`features_compat`). The checksum field itself is zeroed before computation.

Verification algorithm:

1. Copy the label bytes into a mutable buffer.
2. Zero the 32 bytes at the checksum offset.
3. Compute `blake3::hash(&buffer[..checksum_offset])`.
4. Compare against the stored checksum. Mismatch → label is corrupt.

### 4.4 Encoding and decoding

Label encoding writes the struct in little‑endian byte order with no padding
between fields. `pool_name` is a variable‑length UTF‑8 string; its length is

- `magic == b"VBFS"`
- `version == 1` (unknown versions → import refused unless
  `features_incompat` contains only known‑safe bits)
- `checksum` matches recomputed BLAKE3‑256
- `pool_name` is valid UTF‑8 of exactly `pool_name_len` bytes

The type definition and codec live in `tidefs-types-object-store-core` (new
crate) or as a module within `tidefs-local-object-store`.

### 4.5 Feature flags

Three 64‑bit feature flag bitmasks follow the ZFS convention:

- **`features_incompat`**: bits that, if set and unrecognized by this build,
  prevent import. Example: a new checksum algorithm that old code cannot
  verify.
- **`features_ro_compat`**: bits that, if set and unrecognized, allow
  read‑only import but prevent read‑write mount.
- **`features_compat`**: bits that are safe to ignore if unrecognized.

Feature flags are checked at import time against a build‑time feature table
in `tidefs-format-identity`.


## 4A. Key Rust interfaces

### 4A.1 PoolImporter trait

```rust
/// Scans devices, discovers pool topology, and opens a Pool handle.
pub struct PoolImporter;

impl PoolImporter {
    /// Scan a set of candidate device paths for pool labels.
    /// Returns a CandidateDevice for each path that carries a valid label.
    pub fn scan_candidates(device_paths: &[PathBuf]) -> Result<Vec<CandidateDevice>>;

    /// Group candidate devices by pool_guid into candidate pools.
    pub fn group_by_pool_guid(candidates: Vec<CandidateDevice>) -> HashMap<[u8; 16], CandidatePool>;


    /// Select the recovery commit_group: max(commit_group) across all device labels.
    pub fn select_recovery_commit_group(pool: &CandidatePool) -> u64;

    pub fn import_pool(
        candidate: CandidatePool,
        properties: PoolProperties,
        options: &StoreOptions,
    ) -> Result<Pool>;
}
```

### 4A.2 Candidate types

```rust
/// A device found during scan with a valid label.
pub struct CandidateDevice {
    pub path: PathBuf,
    pub capacity_bytes: u64,
    pub label: PoolLabelV1,
    /// Which label copy was used (L0 or L1).
    pub label_source: LabelSource,
}

pub enum LabelSource {
    Label0,
    Label1,
}

/// A group of candidate devices sharing the same pool_guid.
pub struct CandidatePool {
    pub pool_guid: [u8; 16],
    pub pool_name: String,
    /// Keyed by device_index.
    pub devices: BTreeMap<u32, CandidateDevice>,
    /// Majority-vote topology_generation.
    pub topology_generation: u64,
    pub device_count: u32,
    pub max_commit_group: u64,
    pub pool_state: PoolState,
}

    pub valid: bool,
    pub missing_devices: Vec<u32>,
    pub generation_split: Option<(u64, u64)>,
    pub state_consistent: bool,
    pub can_import_degraded: bool,
}
```

### 4A.3 PoolExporter trait

```rust
pub struct PoolExporter;

impl PoolExporter {
    /// Export a pool: quiesce, flush, write EXPORTED labels, verify.
    /// Returns an error if any label write or verification fails.
    pub fn export_pool(pool: &mut Pool) -> Result<()>;
}
```

### 4A.4 DeviceManager trait

```rust
/// Manages online device addition, removal, and replacement within a live pool.
pub struct DeviceManager;

impl DeviceManager {
    /// Add a new device to an active pool.
    /// Labels the new device and performs a commit_group-consistent batch label update
    /// across all existing devices.
    pub fn add_device(
        pool: &mut Pool,
        device_path: &Path,
        class: DeviceClass,
        options: &StoreOptions,
    ) -> Result<DeviceHandle>;

    /// Remove a device from the pool. The device must be evacuated first.
    pub fn remove_device(pool: &mut Pool, device_guid: [u8; 16]) -> Result<()>;

    /// Replace an existing device with a new one (add + rebuild + remove).
    pub fn replace_device(
        pool: &mut Pool,
        old_guid: [u8; 16],
        new_path: &Path,
        rebuild_priority: MaintenancePriority,
        options: &StoreOptions,
    ) -> Result<DeviceHandle>;

    /// Activate a hot-spare to replace a faulted device.
    pub fn activate_spare(
        pool: &mut Pool,
        faulted_guid: [u8; 16],
        policy: &SparePolicy,
        options: &StoreOptions,
    ) -> Result<DeviceHandle>;
}

/// Priority for rebuild/maintenance operations.
pub enum MaintenancePriority {
    Critical,
    High,
    Normal,
    Low,
    Background,
}
```

## 5. PoolState and label lifecycle

### 5.1 State machine

```
               create
                 |
                 v
            +---------+
       +--->| ACTIVE  |<--- import (from EXPORTED)
       |    +----+----+
       |         |
       |         | export
       |         v
       |    +---------+
       +----|EXPORTED |
       |    +----+----+
       |         |
       |         | destroy
       |         v
       |    +---------+
       +----|DESTROYED| (terminal: pool data may be unrecoverable)
            +---------+
```

- **ACTIVE (0)**: pool is in use. All labels carry this state during normal
  operation. Import is refused for ACTIVE pools unless a force flag is set
  (cluster fencing or crash recovery).
- **EXPORTED (1)**: pool was cleanly exported. All labels carry this state;
  the pool is safe to import on any system. Import transitions labels back
  to ACTIVE.
- **DESTROYED (2)**: pool was administratively destroyed. Import is refused
  unless a force flag is set (for data recovery).

### 5.2 Atomicity of state transitions

The key invariant: **all labels on all devices must agree on pool state after
any state transition.** A partially‑written state (e.g., some devices ACTIVE,
others EXPORTED) is a crash‑consistency hazard that the import protocol must
detect and resolve.

Export achieves this through a three‑phase protocol:

1. **Quiesce**: stop accepting new writes; drain in‑flight commit_group commits
2. **Flush**: fsync all devices; write system area checkpoint
3. **Label write**: write both label copies on every device; verify via
   read‑back

If the system crashes during phase 3, the import protocol detects the split
state and resolves by examining `label_commit_group` and `commit_group` fields to determine
which devices got the new label.

## 6. Pool import protocol

### 6.1 Overview

```
                    +------------------+
                    | scan_candidates  |
                    | (open each device|
                    |  path, read L0/L1|
                    |  labels)         |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | group_by_pool    |
                    | (group candidates|
                    |  by pool_guid)   |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | (check device    |
                    |  count, topology |
                    |  generation,     |
                    |  missing devices)|
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | select_recovery  |
                    | (find max commit_group    |
                    |  across labels,  |
                    |  resolve split   |
                    |  state)          |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    | open_pool        |
                    | (read system area|
                    |  root, open each |
                    |  device, rebuild   |
                    |  ClassMap)       |
                    +------------------+
```

### 6.2 Phase 1: scan_candidates

`PoolImporter::scan_candidates(device_paths: &[PathBuf]) -> Vec<CandidateDevice>`

For each candidate path:
1. Open the path as a raw file/block device handle.
2. Read 256 KiB at offset 0 → attempt `decode_label` → `CandidateDevice::Label0`.
3. Read 256 KiB at `capacity - 256 KiB` → attempt `decode_label` → `CandidateDevice::Label1`.
4. If both labels are valid and disagree on `label_commit_group`, select the newer one.
5. If neither label is valid, skip this path (not a pool device, or label
   corruption).
6. Collect device path, capacity, and the winning label into a `CandidateDevice`.

### 6.3 Phase 2: group_by_pool_guid

`group_by_pool_guid(candidates: Vec<CandidateDevice>) -> HashMap<PoolGuid, CandidatePool>`

Group all candidates by `pool_guid`. Each group forms a `CandidatePool`
containing:

- `pool_guid: [u8; 16]`
- `pool_name: String`
- `devices: BTreeMap<u32, CandidateDevice>` keyed by `device_index`
- `topology_generation: u64` (majority vote, see §6.5)
- `device_count: u32`
- `max_commit_group: u64`


For each `CandidatePool`:

1. **Device count check**: `devices.len() == device_count`? If fewer:
   - If the pool has redundancy and missing devices are within tolerance,
     mark it as DEGRADED but importable.
   - If a non‑redundant device is missing, import is refused.
2. **Topology generation consistency**: all present devices must agree on
   `topology_generation` (within ±1 for in‑flight topology changes; see
   §6.5). A split generation signals a partially‑completed device
   add/remove.
3. **Device index uniqueness**: no two devices may share the same
   `device_index`.
4. **State consistency**: all devices must report the same `pool_state`,
   or the split must be resolvable by the recovery phase.

### 6.5 Topology generation and majority vote

`topology_generation` is a monotonically increasing counter that increments
on every device add, remove, or replace. During normal operation, all devices
in a pool carry the same value.

On import, if values differ (crash during a topology change), the import
protocol selects the **majority generation**:

- If ≥ N/2 devices agree on generation G, G wins.
- Devices with a lower generation are stale (they missed the topology change
  that incremented the counter). Their labels are rewritten to G on import.
- If no majority exists (even split), import is refused; the operator must
  force‑import with a risk acknowledgment.

### 6.6 Phase 4: select_recovery_commit_group

The recovery commit_group is the maximum `commit_group` across all labels in the candidate pool:

```
recovery_commit_group = max(devices[*].label.commit_group)
```

This commit_group becomes the starting point for replay. The system area checkpoint at
this commit_group is the authoritative root for pool reconstruction.

The `label_commit_group` field disambiguates which label copy is newer when L0 and L1
differ. The winning copy's `commit_group` is the device's contribution to the recovery
commit_group calculation.

### 6.7 Phase 5: open_pool

`PoolImporter::import_pool(candidate: CandidatePool) -> Result<Pool>`

1. Select the recovery commit_group (from phase 4).
2. Read the system area root block at `system_area_pointer` from the device
   with the highest `commit_group`.
4. For each device in the topology, construct a `DeviceConfig` from the label
   fields (`device_guid`, `device_class`, `device_capacity_bytes`,
   device path).
5. Open each device via `Device::open_single` or `Device::open_mirror` depending
   on `DeviceKind` derived from the label.
6. Rebuild the `ClassMap` (IoClass → device index routing) from per‑device
   `DeviceClass` entries.
7. Construct and return a `Pool` handle with state ACTIVE.

### 6.8 Cross-system portability

Labels use `device_guid` (UUID) for identity, not device paths. The import
protocol accepts devices at any path as long as their GUIDs match. This
enables:

- Moving a pool between servers by physically relocating drives
- Importing a pool after a controller rename (e.g., `/dev/sdb` → `/dev/sdc`)
- Disaster recovery: import from a backup copy of the devices

Device path resolution: the caller provides `device_paths`, and the import
protocol matches them to label `device_guid` values. Unmatched GUIDs
(missing devices) are reported to the operator.

### 6.9 Force import

A `force` flag overrides safety checks:

- Import an ACTIVE pool (crash recovery without clean export)
- Import with missing devices (degraded, data loss possible)
- Import with topology generation split (select highest generation)
- Import a DESTROYED pool (data recovery)

Force import writes a warning to the operator observability channel and
marks the pool as DEGRADED until all issues are resolved.

## 7. Pool export protocol

### 7.1 Overview

`PoolExporter::export_pool(pool: &mut Pool) -> Result<()>`

Export transitions the pool from ACTIVE to EXPORTED with an atomic label
write across all devices.

### 7.2 Protocol phases

1. **Drain writes**: stop accepting new `put`/`delete` operations. Return
   `StoreError::PoolExporting` for new requests.

2. **Quiesce commit_group**: wait for all in‑flight commit_group commits to complete. The commit_group
   state machine enters a QUIESCE phase where no new transactions are opened.

3. **Flush all devices**: call `sync_all()` on every device, ensuring all
   buffered data reaches stable storage.

4. **Write system area checkpoint**: write the final system area root block
   with the current committed commit_group, object index root pointer, and spacemap
   root pointer. fsync the system area.

5. **Write labels**: for each device:
   - Set `pool_state = EXPORTED`
   - Update `label_commit_group` and `commit_group` to the current committed commit_group
   - Encode and write Label 0 at offset 0
   - Encode and write Label 1 at offset `capacity - 256 KiB`
   - fsync each label write
   - Read back and verify checksum

6. **Verify all‑or‑nothing**: read back all labels on all devices. If any
   label read fails or any label still shows `ACTIVE`, the export is
   incomplete. Retry step 5 for the affected devices.

### 7.3 Atomicity guarantee

The export protocol guarantees: **after a successful export, all labels on
all devices carry `pool_state = EXPORTED` with the same `commit_group`.** If the
system crashes mid‑export, the import protocol detects the split state and
resolves it during `select_recovery_commit_group`.

### 7.4 Online export limitation

The current design requires draining all writes (step 1). True online export
(where the pool remains available during the export process) is deferred to a
future design. The v0.417 scope treats export as an offline operation:
no I/O is served during the export window, which is expected to be
milliseconds for the label write phase.

## 8. Online device addition

### 8.1 Protocol

`Pool::add_device(&mut self, device_path: &Path, class: DeviceClass) -> Result<()>`

1. **Label the new device**: construct a `PoolLabelV1` with:
   - `pool_guid` from the existing pool
   - New `device_guid` (random UUID v4)
   - `device_index = current device_count`
   - `topology_generation = current + 1`
   - `device_count = current + 1`
   - `device_class` from the caller's specification
   - `device_capacity_bytes` from the device's actual capacity
   - Current `commit_group` and `label_commit_group`
   - `pool_state = ACTIVE`
   Write both label copies to the new device.

2. **Open the device**: construct `DeviceConfig` from label fields, open via
   `Device::open_single`.

3. **Update existing labels**: for each existing device, update:
   - `topology_generation = current + 1`
   - `device_count = current + 1`
   Write both label copies.

   This update is **atomic within a single commit_group**: all label writes are
   staged, committed in the commit_group SYNC phase, and fsynced together. A crash
   before commit leaves the old labels intact (all devices carry the old
   generation); a crash after commit means the new device's label was written
   and is discoverable on next import.

4. **Rebuild ClassMap**: recompute the `ClassMap` to include the new device
   in the appropriate IoClass routing.

5. **Integrate with allocator**: the spacemap allocator for the new device is
   initialized as fully free. On the next allocation, the pool allocator
   includes the new device in its candidate set.

### 8.2 Consistency invariants

- After successful addition, all devices carry the same `topology_generation`
  and `device_count`.
- The new device's `device_index` is strictly sequential and never reused
  (even if a device with a lower index is later removed).
- If the system crashes during label update (step 3 was partially written),
  the import protocol's majority‑generation rule selects the correct
  generation.

## 9. Online device removal

### 9.1 Precondition: evacuation

A device may only be removed when it holds no live data — or when every live
object on it has been relocated to other devices. Evacuation uses the
cursor‑driven data movement engine (#1239):

1. A cursor iterates over every object key that maps to the target device.
2. For each object, the data is read from the source device, written to a
   destination device (selected by the pool allocator's placement policy),
   and the locator table entry is updated to point to the new location.
3. Deleted objects (tombstones) are skipped.
4. After the cursor completes, a verification pass confirms that no live
   objects remain on the target device.
5. The device's refcount reaches zero; removal can proceed.

Evacuation is budgeted per maintenance tick (#1237) to avoid impacting
foreground I/O. It is resumable: if the system restarts mid‑evacuation, the
cursor position is recovered from a persistent evacuation state record in
the system area.

### 9.2 Protocol

`Pool::remove_device(&mut self, device_guid: [u8; 16]) -> Result<()>`

1. **Verify refcount zero**: check that the target device holds no live
   objects. If objects remain, return `StoreError::DeviceNotEmpty` (the
   caller must evacuate first).
2. **Mark device REMOVED**: set the device's `DeviceState` to `Removed`. The
   device is no longer eligible for new allocations.
3. **Update labels on remaining devices**: for each remaining device, update:
   - `topology_generation = current + 1`
   - `device_count = current - 1`
   Write both label copies within a single commit_group.
4. **Update labels on removed device**: write labels with `pool_state` set
   to a `REMOVED` marker (or clear the label entirely — implementation
   choice TBD). The removed device must not be rediscovered on the next
   import.
5. **Rebuild ClassMap**: recompute routing without the removed device.
6. **Close the device**: drop the `Device` handle, releasing file descriptors.

### 9.3 Device index stability

Removed device indices are **not reused**. The remaining devices keep their
original `device_index` values. This means `device_index` is a stable
identifier across the lifetime of the pool, which simplifies locator table
references and external tooling.

## 10. Online device replacement

### 10.1 Protocol

`Pool::replace_device(&mut self, old_guid: [u8; 16], new_path: &Path) -> Result<()>`

Device replacement is a composite of add and remove:

1. **Add the new device** (§8): label, open, integrate into topology with
   `topology_generation + 1`.
2. **Rebuild data onto the new device**:

   - **Redundant devices (mirrors)**: for each mirror member, copy the entire
     contents from a healthy member to the new device. This is a bulk copy
     — no object‑level iteration required.
   - **Non‑redundant devices (singles)**: an evacuation + re‑add pattern:
     data is evacuated from the old device to other devices, then the new
     device participates in future allocations. No in‑place rebuild is
     possible without redundancy.

   Rebuild is budgeted per maintenance tick (#1237). During rebuild, the
   device operates in DEGRADED state (reads served from healthy members,
   writes go to all members including the rebuilding one).

3. **Verify rebuild completeness**: after the rebuild cursor completes, a
   checksum comparison confirms the new device matches healthy members (for
   mirrors) or that the old device is empty (for singles).

4. **Remove the old device** (§9): evacuation (if not already done),
   refcount zero gate, label update, close.

### 10.2 Rebuild priority

Rebuild of a replacing device runs at `MaintenancePriority::Critical`,
above regular scrubbing and below foreground I/O. The operator can adjust
priority through the ADMIN service.

## 11. Hot-spare auto-activation

### 11.1 SparePolicy

```rust
pub enum SparePolicy {
    /// Never auto-activate spares; require operator intervention.
    Manual,
    /// Activate a spare when any non‑spare device enters FAULTED state.
    AutoOnFault,
    /// Activate a spare when any non‑spare device enters FAULTED or DEGRADED
    /// with persistent errors exceeding a threshold.
    AutoOnDegraded { error_threshold: u64 },
}
```

### 11.2 Activation algorithm

1. The pool health monitor detects a device entering FAULTED or DEGRADED
   state (see §12).
2. If `SparePolicy` permits auto‑activation, scan the topology for devices
   with `DeviceClass::Spare`.
3. Select the best spare: matching or larger capacity, same or faster
   device class, lowest `device_index`.
4. Call `Pool::replace_device(faulted_guid, spare_path)`.
5. The old faulted device is removed after rebuild completes.
6. An operator notification is emitted: "spare activated for device <guid>,
   rebuild in progress."

### 11.3 Spare inventory

Spare devices carry `DeviceClass::Spare` in their labels and are enumerated
during import. They do not participate in normal I/O routing (they are
excluded from all `ClassMap` entries). A spare becomes a normal data device
after activation: its `DeviceClass` is updated to match the device it
replaced.

If multiple faults occur and spare inventory is exhausted, the pool enters
DEGRADED or FAULTED state depending on redundancy.

## 12. Device failure handling

### 12.1 Error detection

The device I/O path (`DeviceImpl::put`, `DeviceImpl::get`, `DeviceImpl::delete`)
returns `StoreError` on failure. The pool wrappers (`Pool::put`,
`Pool::get`, `Pool::delete`) catch these errors and update per‑device error
counters:

```rust
pub struct DeviceStatus {
    pub state: DeviceState,
    pub last_error: Option<String>,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
}
```

Error counting uses an exponential decay window: errors older than
`ERROR_WINDOW_SECS` are aged out to prevent transient bursts from causing
permanent state transitions.

### 12.2 State machine

```
                         errors exceed threshold
    +---------+         (redundant device only)       +----------+
    | ONLINE  | ----------------------------------> | DEGRADED |
    +----+----+                                     +-----+----+
         |                                                |
         | errors exceed threshold                        | errors continue,
         | (non-redundant device) or                        | redundancy lost
         | all mirrors faulted                            |
         v                                                v
    +---------+                                     +----------+
    | FAULTED | <---------------------------------- | FAULTED  |
    +----+----+    errors on DEGRADED device        +-----+----+
         |           exhaust redundancy                   |
         |                                                |
         +-------- manual reactivation -------------------+
                  (operator clears error counters)
```

- **ONLINE → DEGRADED**: I/O errors exceed `DEGRADE_THRESHOLD` on a device
  that has redundancy (mirror, or erasure‑coded with spare parity). The
  device still serves reads from healthy members and writes to all members.
- **DEGRADED → FAULTED**: errors continue and redundancy is exhausted (all
  mirror members faulted, or parity insufficient to reconstruct). The device
  stops serving I/O.
- **ONLINE → FAULTED**: errors exceed `FAULT_THRESHOLD` on a non‑redundant
  device. Immediate fault.
- **FAULTED → ONLINE**: operator manually clears error counters after
  resolving the underlying issue (e.g., replacing a failed disk, re‑seating
  a cable).

### 12.3 Operator notification

State transitions emit structured events through the observability pipeline
(`tidefs-observe-core-runtime`):

```rust
pub struct DeviceStateChangeEvent {
    pub timestamp: SystemTime,
    pub pool_guid: [u8; 16],
    pub device_guid: [u8; 16],
    pub device_index: u32,
    pub from: DeviceState,
    pub to: DeviceState,
    pub last_error: Option<String>,
    pub error_count: u64,
}
```

The ADMIN service and operator dashboards consume these events for alerting
and runbook execution.

### 12.4 Pool-level health aggregation

`Pool::health()` aggregates per‑device states:

| Device states | PoolHealth |
|---|---|
| All ONLINE | Online |
| ≥1 DEGRADED, 0 FAULTED | Degraded |
| ≥1 FAULTED, data still accessible via redundancy | Degraded |
| ≥1 FAULTED, data loss possible | Faulted |
| Administratively suspended | Suspended |

## 13. Cluster-aware pool ownership

### 13.1 Design principle

Pool ownership is **orthogonal to cluster membership**. A pool can be:

- **Standalone**: imported on a single node; no cluster coordination.
- **Cluster‑attached**: imported on a node that is a member of a tidefs
  cluster; the pool is owned by that node until exported or failed over.

Cluster membership (#1283) governs which nodes can communicate. Pool
ownership governs which node may read/write a specific pool.

### 13.2 Cluster import

`PoolImporter::import_pool_cluster(candidate, membership) -> Result<Pool>`

1. Verify that this node is a member of the cluster.
2. Acquire a **pool lease** from the distributed lock service (#1248).
   The lease is a short‑lived (renewable) exclusive lock on the pool GUID.
3. On lease acquisition, proceed with the standard import protocol (§6).
4. Register the pool with the cluster membership service: "Node X owns
   pool Y."
5. Periodically renew the lease. If the lease expires (node failure, network
   partition), the pool is fenced: all further I/O returns
   `StoreError::PoolFenced`.

### 13.3 Cluster export

Cluster export additionally:

1. Revoke the pool lease in the distributed lock service.
2. Unregister pool ownership from the membership service.
3. Proceed with the standard export protocol (§7).

### 13.4 Failover

When a node fails (lease expires, heartbeat lost), the cluster may reassign
the pool to another node:

1. The membership service detects the failure.
2. The new owner acquires the pool lease.
3. The new owner imports the pool (devices must be accessible from the new
   node — shared SAS, iSCSI, NVMe‑oF, or RDMA).
4. Replay from the recovery commit_group to catch up on any writes that were
   committed before the old node failed.

Failover depends on **shared storage** (devices accessible to both nodes) or
**replicated storage** (each node has its own copy, kept in sync via the
replication pipeline, #1249).

## 14. Integration with the commit_group state machine

### 14.1 Label write on commit_group commit

Label writes are piggybacked on the commit_group commit cycle (#1267). On each
committed commit_group:

1. Data payloads for the commit_group are flushed to devices.
2. Metadata roots are written to the system area.
3. Labels on all devices are updated: `label_commit_group = committed_commit_group`, `commit_group =
   committed_commit_group`.
4. A checkpoint pointer in the system area root block records the committed
   commit_group.

This ensures that labels always reflect the latest committed state. If the
system crashes, the import protocol selects the maximum `commit_group` across labels
as the recovery point — which is exactly the last committed commit_group.

### 14.2 Topology changes within a commit_group

A topology change (add/remove/replace) is encapsulated in a single commit_group:

1. Open a new commit_group.
2. Stage the label updates (new device labels + existing device label
   changes).
3. Commit the commit_group: flush labels, write checkpoint, fsync.
4. The topology change is now durable.

If the system crashes mid‑commit_group, the old labels are intact (the new commit_group was
never committed). The import protocol sees the old topology and operates
correctly.

## 15. Forward and backward compatibility

### 15.1 Version negotiation

The `version` field in `PoolLabelV1` allows future label format changes:

- **Import**: if `version > supported_version`, check `features_incompat`.
  If no unknown incompat bits are set, allow read‑only import. Otherwise,
  refuse import.
- **Write**: always write the current `version` (1). Never downgrade a
  label.

### 15.2 Feature flag upgrade path

When a new feature is introduced:

1. The feature gets a bit in one of the three feature flag masks, depending
   on compatibility.
2. The feature is implemented behind an "enable at pool creation or upgrade"
   gate.
3. Once enabled, the feature bit is set in all device labels.
4. A pool upgrade (`tidefs pool upgrade <pool>`) sets the feature bit and
   performs any on‑disk format migration.

### 15.3 DeviceClass forward compatibility

The `device_class` field is a `u8`. Implementations map known values (0–6) to
`DeviceClass` variants. Unknown values map to an `Unknown(u8)` variant, which
the pool treats as a generic data device. This allows new device classes in
future label versions without breaking import.

## 16. Implementation plan (7-phase)

Per-metaslab parallelism is explicitly deferred from this plan. Each phase
below delivers sequential, single-threaded pool operations. Parallel
metaslab allocation, concurrent device I/O scheduling, and per-core metadata
accumulation are deferred to the metadata engine parallelism design
(#1278) and spacemap allocator wire-up issues.

| Phase | Issue scope | Description | Depends on |
|---|---|---|---|
| 1 | 1 issue | `PoolLabelV1` type + BLAKE3 codec in `tidefs-types-object-store-core`; encode/decode/checksum roundtrip tests | — |
| 3 | 1 issue | **Pool export**: `export_pool()` (quiesce datasets, flush commit_group, atomic label write, verify); three-phase export protocol with crash-resilient import detection | Phase 2 |
| 4 | 1 issue | **Online device addition**: `add_device()` (label new device, update existing labels in commit_group batch, rebuild ClassMap, atomically commit across all pool devices) | Phase 3 |
| 5 | 2–3 issues | **Online device removal**: data evacuation engine (cursor‑driven, budgeted per tick, resumable after restart) + `remove_device()` (evacuation precondition, refcount gate, label update, topology generation increment) | Phase 4, #1239, #1237 |
| 6 | 2–3 issues | **Device replacement, hot‑spares, and failure handling**: `replace_device()` (add‑new + rebuild + remove‑old composite), `SparePolicy` auto‑activation, error‑counting state machine (ONLINE→DEGRADED→FAULTED), observability events | Phase 4, Phase 5 |

### 16.1 Per-metaslab parallelism (explicitly deferred)

This design specifies sequential pool operations only. The following
parallelism dimensions are deferred:

- **Metaslab-level allocation**: per-metaslab cursors and `MetaslabAllocator`
  are defined in the spacemap/allocator design (#1189, #1693); pool device
  management does not depend on metaslab parallelism.
- **Concurrent device I/O**: multi-device striping and I/O scheduling are
  deferred to the data-path parallelism design.
- **Per-core metadata accumulation**: tracked in metadata engine parallelism
  design (#1278).

All phase deliverables in this plan operate correctly with a single-threaded
allocation and I/O path. When per-metaslab parallelism lands, pool device
management (add, remove, replace) remains unchanged — only the underlying
allocator's internal concurrency model changes.

### 17.1 Unit tests (per phase)

- `PoolLabelV1` encode/decode roundtrip with valid and invalid inputs
- Checksum verification: correct checksum passes, corrupted checksum fails
- Label L0/L1 redundancy: read from either copy, prefer newer `label_commit_group`

### 17.2 Integration tests

- **Export/import roundtrip**: create pool, write data, export, import on
  different paths, verify all data checksums match
- **Export atomicity**: simulate crash during label write; verify import
  detects split state and resolves correctly
- **Device add**: create pool with 1 device, add a second, verify
  `device_count` and `topology_generation` consistent across labels, verify
  data written to new device is readable
- **Device remove**: create pool with 2 devices, evacuate one, remove it,
  verify remaining device's labels updated, verify all data accessible
- **Device replace (mirror)**: create mirror pool, replace a member, verify
  rebuild completes, verify data integrity
- **Hot‑spare**: create pool with spare, fault a device, verify
  auto‑activation, verify rebuild completes
- **Failure handling**: inject I/O errors, verify state transitions
  (ONLINE → DEGRADED → FAULTED), verify observability events emitted
- **Cross‑system portability**: export pool, move devices to different
  paths, import with new paths, verify data integrity

### 17.3 xtask gates

- `tidefs-xtask check-pool-import-export`: runs the full integration test
  suite above
  majority vote, device_count consistency, device_index uniqueness
- `tidefs-xtask check-label-corruption`: injects label corruption and
  verifies import detects and reports it

## 18. ZFS/Ceph Prior-Art Analysis

This section is a design-pressure comparison only. The TideFS column describes
targets in this specification, not validated current implementation, parity,
superiority, production availability, lower operational cost, or complete online
device lifecycle support. Product-facing incumbent comparisons remain blocked
behind #875 claim ids and #928/#930 comparator evidence.

| Dimension | ZFS prior art | Ceph prior art | TideFS design target |
|---|---|---|---|
| Label format | 256 KiB device_label, 4 copies | None (monitor cluster) | 256 KiB PoolLabelV1, 2 copies, BLAKE3‑256 |
| Import mechanism | `zpool import -a` scans all devices | OSDs connect to monitors | Label‑driven scan + pool_guid grouping; portable |
| Export | Offline: unmount datasets, write labels | N/A (no pool export) | Offline: quiesce, flush, atomic label write |
| Device addition | `zpool add` | `ceph osd create` | Online: label + commit_group‑consistent batch update |
| Device removal | Post‑0.8.0, mirror‑only | `ceph osd out` + rebalance | Online: evacuation + refcount gate + label update |
| Device replacement | `zpool replace` (manual) | `ceph osd destroy` + new OSD | Online: add‑new + rebuild + remove‑old composite |
| Hot‑spare | External `zed` scripting | CRUSH map `device class` | Built‑in `SparePolicy` with auto‑activation |
| Failure handling | zed event → `device state` | Monitor marks OSD down | I/O error → state machine → observability event |
| Cluster integration | None (single‑node) | Native (monitor cluster) | Hybrid: standalone or cluster mode; pool lease |
| Cross‑system portability | Yes (label‑driven) | No (monitor‑bound) | Target: label-driven with device_guid identity |

## 19. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Label write atomicity violation on crash | Medium | High | Two‑copy redundancy, import‑time state resolution, `label_commit_group` disambiguation |
| Split topology generation after partial add/remove | Low | Medium | Majority‑vote rule on import, force‑import escape hatch |
| Evacuation cursor fails mid‑operation | Medium | Medium | Persistent cursor state, resumable after restart, budgeted per tick |
| Cluster lease expiry during active I/O | Low | High | Fencing on expiry, write‑side lease check before commit_group commit |
| Label format version mismatch across cluster | Low | Medium | Feature flag bits, version negotiation, read‑only fallback |
| Device class forward‑compatibility gap | Low | Low | `Unknown(u8)` variant, treated as generic data device |

## 20. Non‑claims (explicit boundaries)

- This design does not include the data evacuation engine implementation
  — tracked in #1239, #1229, #1241.
- This design does not cover erasure coding redundancy or rebuild algorithms
  — tracked in #1249.
- This design does not specify the ADMIN service protocol or replicated commit_group
  commit — tracked in #1243 and cluster design suite.
- This design does not change the local filesystem's single‑device I/O path;
  multi‑device allocation and I/O scheduling are deferred to their
  respective issues.
- This design does not include pool geometry conversion (mirror ↔ erasure
  coding) — tracked in #1275.
