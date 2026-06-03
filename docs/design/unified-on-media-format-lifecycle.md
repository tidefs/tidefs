
**Issue**: [#1238](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1238)
**Status**: design-spec
**Priority**: P1
**Lane**: docs
**Maturity**: design-spec — meta-framework coordinating #1220, #1223, #1225, #1222, #1224, #1185, #1235, #1236

## Abstract

This document defines the unified five-phase lifecycle that governs every
on-media record format in tidefs. It is the meta-framework that coordinates
the individual format mechanisms — record families, feature flags, TLV
extensions, rebake, golden vectors, trace oracle, and torn-commit recovery —

This is a **process and contract design** that establishes hard rules all
format work must obey. It does not duplicate the detail of individual format
docs; it defines the rules that connect them.

## Relationship to existing docs

| Document | Role | Phase |
|---|---|---|
| `docs/design/on-media-format-strategy.md` (#1220) | Record family catalogue, TLV rules, encoding | 1, 3 |
| `docs/DATASET_FEATURE_FLAGS_DESIGN.md` (#1223) | Feature class model, mount gating | 2 |
| `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` (#1225) | Example record family through full lifecycle | 1–5 |
| (pending) trace oracle spec (#1235) | Cross-implementation semantic equivalence | 5 |
| (pending) RFP-Core methodology (#1236) | Python oracle mirror rule | cross-cutting |

This document is the **authoritative lifecycle**. The individual format docs
remain canonical for their detailed domains.

---

## Architecture Overview

The five-phase lifecycle maps to the existing crate structure:

```
┌──────────────────────────────────────────────────────────────────────┐
│                     UNIFIED FORMAT LIFECYCLE                         │
├───────────┬───────────┬──────────────┬───────────────┬───────────────┤
│  Phase 1  │  Phase 2  │   Phase 3    │   Phase 4     │   Phase 5     │
├───────────┼───────────┼──────────────┼───────────────┼───────────────┤
│ on-media- │ dataset-  │ binary_      │ background-   │ trace-oracle  │
│ format-   │ feature-  │ schema-      │ scheduler     │ crash-        │
│ strategy  │ flags     │ core         │ rebake (TBD)  │ injection-    │
│ .md       │ crate     │ framing      │ reclaim       │ harness       │
│           │           │ crate        │ crate         │ golden-       │
│           │           │              │               │ vectors       │
├───────────┴───────────┴──────────────┴───────────────┴───────────────┤
│                        SHARED CONTRACTS                              │
│  binary_schema-core (endian, checksum, alignment)                    │
│  P2-03 binary law │ P2-04 format identity │ P2-01 type map           │
└──────────────────────────────────────────────────────────────────────┘
```

### Crate to Phase Mapping

| Crate | Phase | Role |
|---|---|---|
| `tidefs-types-dataset-feature-flags-core` | 2 | `FeatureClass`, `FeatureName`, `FeatureFlagValueV1`, `CANONICAL_V1_FEATURES` |
| `tidefs-dataset-feature-flags` | 2 | `FeatureFlags` runtime, mount gating, B+tree persistence |
| `tidefs-binary_schema-core` | 1,3 | `SchemaFamilyId`, `SchemaTypeId`, `U64Le`, `ChecksumProfile`, `ContinuityWindow` |
| `tidefs-binary_schema-framing` | 1,3 | `EnvelopeHeader`, `SectionHeader`, `ChunkFrameHeader` encode/decode |
| `tidefs-binary_schema-checksum` | 1,3 | CRC32C and BLAKE3-256 domain-separated checksum functions |
| `tidefs-extent-map` | 1 | Extent map implementation (tristate model) |
| `tidefs-types-extent-map-core` | 1 | Extent map type authority |
| `tidefs-trace-oracle` | 5 | Trace emission and replay engine |
| `tidefs-online-verifier` | 5 | Online integrity verification |
| `tidefs-background-scheduler` | 4 | Scheduler hosting rebake and other background jobs |
| `tidefs-reclaim` | 4 | Safe space reclamation (feeds rebake free-space budget) |

---

## Lifecycle State Machine

Each format change proposal (record type, TLV, feature flag, or migration)
moves through a deterministic state machine. The lifecycle is a **DAG of
phase transitions**, not a linear pipeline — a proposal can be in Phase 3
(Evolve) for one TLV while still in Phase 1 (Define) for another.

### Formal state model

```
 ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
 │ PROPOSED │────▶│ DEFINED  │────▶│  GATED   │────▶│ EVOLVING │────▶│MIGRATING │
 └──────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘
                       │                                    │              │
                       │                                    │              │
                       └────────────────────────────────────┴──────────────┘
                                               │
                                               ▼
                                        ┌──────────┐     ┌──────────┐
                                        └──────────┘     └──────────┘
```

| State | Meaning | Entry condition | Exit condition |
|---|---|---|---|
| `PROPOSED` | Format change idea exists | Design issue filed | Design doc with field layout table committed |
| `DEFINED` | Record type / TLV fully specified | All Phase-1 exit criteria met | Feature name registered in `CANONICAL_V1_FEATURES` |
| `GATED` | Feature flag gates the format | Mount algorithm handles the flag | Unit tests cover all mount scenarios |
| `EVOLVING` | TLV encode/decode live | TLV type in registry, old-reader skip passes | TLV ordering + size limits enforced |
| `MIGRATING` | Rebake converting old→new | Scanner detects old-format records | Atomic CoW swap verified, crash-recovery tested |
| `DONE` | Format change is production-ready | All exit criteria met | Issue closed, `docs/STATUS.md` updated |

### Phase transition rules

1. **PROPOSED → DEFINED**: irreversible. Once a record layout is committed to
   the design book, it becomes the specification. Later changes are new TLV
   extensions.
2. **DEFINED → GATED**: requires the feature flag to be registered. A defined
   but un-gated format cannot appear on media.
3. **GATED → EVOLVING**: applies only if the format defines TLVs. Formats
   with no TLV extensions skip directly to MIGRATING (if migration needed)
4. **EVOLVING → MIGRATING**: applies only if the TLV change requires on-media
   migration (e.g., deprecated TLV stripping, new compression).

### State tracking

The lifecycle state of each format change is tracked in Forgejo labels and
the issue body checklist. There is no runtime lifecycle registry; the
design-time process is enforced by the issue template and code review.



## Phase 1: Define (Format Specification)

### Purpose

A record family is defined before it can appear on media. The definition
includes record types, encoding rules, feature flag requirements, and
golden vectors.

### Entry criteria

- A design issue exists describing the record family
- The record family is registered in the V1 record family catalog
  (`docs/design/on-media-format-strategy.md` §1)

### Required deliverables

For each record type in the family:

1. **Fixed-width prefix**: family_id (2 bytes), type_id (2 bytes), record_len
   (4 bytes) — matching the `binary_schema-core` dispatch prefix.
2. **Field layout table**: offset, size, type, and description for each field
   in the fixed prefix. See #1220 §1.2 for the canonical catalog format.
3. **Encoding rules**: little-endian scalars, CRC32C checksum of the fixed
   prefix, alignment to 8-byte boundaries.
4. **Feature flag assignment**: a named feature flag (reverse-DNS,
   `org.tidefs:<name>`) registered in `CANONICAL_V1_FEATURES`, with a
   justified compatibility class (compat/ro_compat/incompat).
5. **Golden vectors**: minimum 3 encode/decode pairs per record type,
   committed alongside the specification. See #1185.

### Exit criteria

- [ ] Field layout table complete for all record types
- [ ] Feature name registered in `CANONICAL_V1_FEATURES`
- [ ] Feature class justified with classification decision tree
- [ ] Golden vectors committed (≥3 encode/decode pairs per record type)
- [ ] Python reference implementation updated

### Reference

See `docs/design/on-media-format-strategy.md` for the complete V1 record
family catalog, TLV extension rules, byte-order policy, checksum framing,
and versioning policy.

---

## Phase 2: Gate (Feature Flags)

### Purpose

Before a record family can be used at runtime, the engine must check that
its feature flag is enabled for the dataset. The mount algorithm decides
whether the dataset can be opened read-write, read-only, or must be refused.

### Mount algorithm

As specified in #1223:

1. Read the dataset's feature flags (three B+trees: compat, ro_compat, incompat).
2. Compute the intersection of engine-supported flags and dataset-enabled flags.
3. If any dataset `incompat` flag is not in the engine's supported set: **refuse mount**.
4. If any dataset `ro_compat` flag is not in the engine's supported set and the
   mount is requested read-write: **force read-only mount**.
5. Enable all `compat` flags and all supported `ro_compat`/`incompat` flags.

### Feature class decision tree

When classifying a new feature:

| Question | Answer | Class |
|---|---|---|
| Does it change how existing records must be interpreted? | Yes | `incompat` |
| Are writes unsafe without understanding, but reads remain safe? | Yes | `ro_compat` |
| Is it purely additive (can be silently ignored)? | Yes | `compat` |

### Feature lifecycle stages

1. **Proposed**: feature is designed, TLV types registered.
2. **Experimental**: feature flag reserved, only enabled with `-o experimental_features=1`.
3. **Stable**: feature flag is part of the standard set.
4. **Deprecated**: new datasets cannot enable it; old datasets can still mount.
5. **Removed**: feature flag retired; datasets must be converted before upgrade.

### Exit criteria

- [ ] Feature name merged into `CANONICAL_V1_FEATURES` constant
- [ ] `FeatureFlags::check_mount()` handles the new feature correctly
- [ ] Unit tests cover all mount scenarios (known RW, unknown incompat refuses,
      unknown ro_compat forces RO, unknown compat ignored)

### Reference

See `docs/DATASET_FEATURE_FLAGS_DESIGN.md` for the full feature flag
architecture, B+tree storage layout, and upgrade semantics.

---

## Phase 3: Evolve (TLV Extensions)

### Purpose

Records carry a TLV (Type-Length-Value) trailer after the fixed prefix,
enabling forward-compatible extension without per-record version churn.

### TLV rules (from #1220 §2)

1. **Self-describing**: every TLV carries a 2-byte type code and 2-byte length
   after the type/length header. Unknown TLVs are mechanically skipped.
2. **Ascending order**: TLVs are ordered by type code at encode time.
   Violation at decode time is a `CorruptRecord` error.
3. **Terminator**: `(type=0, length=0)` is mandatory at the end of every TLV area.
4. **Size limit**: total TLV area must not exceed 4096 bytes per record.
5. **Deprecation**: a record family may deprecate a TLV by marking it "ignored"
   in a newer dataset version. Deprecated TLVs are skipped at decode.

### Entry criteria

- A record family exists with a defined fixed prefix
- The new TLV type is registered in the TLV type registry
- The feature flag gating the TLV is assigned

### Exit criteria

- [ ] TLV type registered in the TLV type registry
- [ ] Feature flag associated with the TLV
- [ ] TLV encode/decode implemented
- [ ] Old-reader skip test passes
- [ ] TLV ordering invariant checked at encode time
- [ ] TLV size limit checked at decode time

### Reference

See `docs/design/on-media-format-strategy.md` §2 for the full TLV encoding
rules, forward-compat guarantees, and deprecated-TLV lifecycle.

---

## Phase 4: Migrate (Rebake)

### Purpose

When format rules change in a way that existing on-media data must be
transformed, rebake provides an incremental, non-blocking migration path.
Old records remain readable (via compat/ro_compat), new writes use the
new format, and a background process converts old records over time.

### Migration scenarios

| Scenario | Old format | New format | Rebake action |
|---|---|---|---|
| New compression | no compression | LZ4 | Recompress extent data, update ExtentMapEntry |
| New checksum | CRC32C | BLAKE3-256 | Re-checksum all DATA extents |
| New shard layout | 1-replica flat | 3-replica EC(2,1) | Re-encode extents into EC shards |
| Deprecated TLV | TLV present | TLV ignored | Strip deprecated TLV from records |
| Ingest→base | Journal records | Base shard records | Convert ingest journal extents to base shard extents |

### Rebake architecture

Rebake is a **background job** managed by `tidefs-background-scheduler`. It
operates as a three-stage pipeline:

1. **Scanner**: Walk datasets, identify records using the old format.
2. **Planner**: Determine the target format and check free-space budget.
3. **Converter**: In a transactional context, allocate new-format storage,
   write new data, atomically swap the record pointer (CoW), and defer
   reclamation of old storage.

All stages operate under configurable per-tick budgets to avoid starving
foreground I/O.

### Invariants

1. **No data loss window**: old records remain readable until the new record
   is fully committed. The swap is atomic (CoW pointer update).
2. **Crash safety**: if the engine crashes mid-rebake, recovery replays the
   commit_group log and either completes or rolls back the partial conversion.
3. **Incremental progress**: rebake can be interrupted and resumed. The
   scanner cursor persists across ticks.
4. **Feature-gated**: rebake of a feature's records is only active when the
   feature flag is enabled.
5. **Space budget**: rebake yields to the reclaim cleaner when free space
   falls below target.

### Feature reclassification path

Rebake enables `ro_compat` features to eventually migrate to `compat`:

1. Feature introduced as `incompat` during development.
2. Once stable and rebake-ready, reclassified to `ro_compat`.
3. After all datasets are rebaked, optionally reclassified to `compat`.
4. A feature is never reclassified to `incompat` after `ro_compat`/`compat` release.

### Exit criteria

- [ ] Rebake scanner identifies all old-format records
- [ ] Rebake converter correctly produces new-format records
- [ ] Atomic swap (CoW pointer update) verified
- [ ] Crash recovery test: crash mid-rebake, restart, verify consistency
- [ ] Space budget enforcement verified

### Reference

See #1222 for the full rebake engine design.

---


### Purpose

before it can be considered production-ready.


#### 5.1 Golden vectors (#1185)

Byte-for-byte encode/decode correctness. Requirements:
- Minimum 3 encode/decode pairs per record type.
- Cover: empty/default, typical, and maximum-size records.
- Cover: all valid TLV combinations.
- Golden vectors are **append-only** — never modified, only added.

#### 5.2 Trace oracle (#1235)

Cross-implementation semantic equivalence. The trace oracle:
- Emits structured trace events from both Rust and Python implementations.
- Replays and compares the trace streams.
- Flags semantic divergence (same input, different output).

#### 5.3 Torn-commit recovery (#1224)

Journal integrity after crash at any format boundary. The deterministic
crash injection harness:
- Commits a COMMIT_GROUP with format-changing operations.
- Injects a crash at a specific boundary (pre-commit, mid-commit, post-commit).
- Verifies that recovery produces a consistent dataset.

### Exit criteria

- [ ] All golden vectors pass
- [ ] Trace oracle replay passes (Python ↔ Rust cross-implementation)
- [ ] Crash injection at format boundaries passes (≥3 crash seeds)
- [ ] Online verifier coverage updated for new record type

---

## Data Structures

The following Rust types, traits, and constants realize the lifecycle
framework in code. They are **design-time and runtime contracts** that
connect the lifecycle phases to concrete crate boundaries.

### Core type authority (`tidefs-types-dataset-feature-flags-core`)

```rust
/// Feature compatibility class: governs mount decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureClass { Compat, RoCompat, Incompat }

/// Feature enablement state on a dataset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureFlagValueV1 { Enabled, EnabledActive }

/// Reverse-DNS feature name (≤127 bytes).
pub struct FeatureName([u8; FEATURE_NAME_MAX_LEN]);

/// Per-dataset feature B+tree roots, stored in DatasetRecord TLV area.
pub struct DatasetFeatureFlagsV1 {
    pub compat_btree_root: BtreeRootPointer,
    pub ro_compat_btree_root: BtreeRootPointer,
    pub incompat_btree_root: BtreeRootPointer,
}

/// Canonical feature name registry — the single source of truth.
pub const CANONICAL_V1_FEATURES: &[&str] = &[
    "org.tidefs:extent_map_tristate",
    "org.tidefs:posix_acl",
    "org.tidefs:polymorphic_xattr",
    // ...
];
```

### Binary schema authority (`tidefs-binary_schema-core`)

```rust
/// Magic bytes for all V1 enveloped data: "VBFS" = 0x5346_4256
pub const BINARY_SCHEMA_MAGIC: u32 = 0x5346_4256;

/// Dispatch prefix: every record starts with these 8 bytes.
/// family_id: u16 LE, type_id: u16 LE, record_len: u32 LE
pub struct SchemaFamilyId(pub u64);   // namespace for record families
pub struct SchemaTypeId(pub u64);     // specific record type within family

/// Format version counter: (major, minor).
pub struct SchemaVersion { pub major: u16, pub minor: u16 }

/// Fixed-width LE scalar macros: U16Le, U32Le, U64Le
/// All on-media integers are little-endian with canonical encoding.
```

### Feature flag runtime (`tidefs-dataset-feature-flags`)

```rust
/// Outcome of the mount-time feature compatibility check.
pub enum MountCheckResult { OkRw, ForceRo, RefuseMount }

/// In-memory representation of a dataset's enabled features.
pub struct FeatureFlags {
    compat: BTreeMap<FeatureName, FeatureFlagValueV1>,
    ro_compat: BTreeMap<FeatureName, FeatureFlagValueV1>,
    incompat: BTreeMap<FeatureName, FeatureFlagValueV1>,
}

impl FeatureFlags {
    /// The mount gate: determines whether a dataset can be opened.
    pub fn check_mount(&self) -> MountCheckResult;

    /// One-way enablement: feature cannot be disabled after enabling.
    pub fn enable_feature(&mut self, name: FeatureName, class: FeatureClass)
        -> Result<(), FeatureFlagsError>;

    /// Persist feature flags to per-dataset B+trees.
    pub fn persist(&self, store: &mut Pool)
        -> StoreResult<DatasetFeatureFlagsV1>;

    /// Load feature flags from per-dataset B+trees.
    pub fn load(store: &Pool, roots: &DatasetFeatureFlagsV1)
        -> StoreResult<FeatureFlags>;
}
```

### Trace oracle (`tidefs-trace-oracle`)

```rust
/// A single trace event: operation name + structured JSON payload.
pub struct TraceEvent {
    pub op_name: String,
    pub payload: serde_json::Value,
    pub timestamp_ns: u64,
    pub sequence: u64,
}

/// Replays a trace file and returns the event stream.
pub struct TraceRunner {
    pub fn run_trace(&mut self, trace_path: &Path)
        -> Result<Vec<TraceEvent>, TraceError>;
}

/// Writes a JSONL trace file for oracle comparison.
pub struct JsonlTraceWriter {
    pub fn write_op(&mut self, op: &serde_json::Value)
        -> Result<(), TraceError>;
}
```

### Lifecycle state (design-time, not compiled)

The lifecycle state itself is not encoded in Rust types — it is a
**process contract** tracked in Forgejo. However, the format change
proposal template defines a canonical checklist structure that all format
change issues must follow. The checklist items map 1:1 to the phase exit
criteria defined in this document.

---

## Compliance Model

The lifecycle framework enforces compliance through three layers:

### Layer 1: Design-time (issue template)

Every format change issue must include the Format Change Proposal Template
checklist. The checklist items are gated by the exit criteria in this
document. A reviewer verifies each checkbox before advancing the issue.

### Layer 2: Compile-time (Rust type system)

- **Feature flags are gated by `CANONICAL_V1_FEATURES`**: the `FeatureName::new`
- **Binary schema dispatch is type-safe**: `SchemaFamilyId` and `SchemaTypeId`
  are newtype wrappers that prevent accidental mixing of record families.
- **TLV size limits are enforced at decode**: the `binary_schema-framing` crate
  checks total TLV area ≤ 4096 bytes at decode time.

### Layer 3: Runtime (mount gate)

- **Mount algorithm refuses incompatible datasets**: `FeatureFlags::check_mount()`
  is called at pool open and dataset mount. No I/O path can execute without
  passing the mount gate.
- **Online verifier detects format violations**: `tidefs-online-verifier`
  periodically scans records for structural integrity, including TLV ordering
  and size invariants.

### Audit trail

Every format change leaves an audit trail:

| Artifact | Location | Purpose |
|---|---|---|
| Design doc | `docs/design/` | Specification of record types, TLVs, encoding rules |
| Golden vectors | `crates/*/tests/golden/` | Byte-for-byte encode/decode reference |
| Feature flag registration | `CANONICAL_V1_FEATURES` constant | Compile-time assertion that the flag exists |
| Mount gate test | `crates/tidefs-dataset-feature-flags/tests/` | Verifies mount algorithm behavior |

### Pre-submission checklist for reviewers

When reviewing a format change that claims to have completed the lifecycle:

1. **Define**: Is the field layout table in the design doc? Are encoding rules
   explicit (byte order, alignment, checksum domain)?
2. **Gate**: Does `CANONICAL_V1_FEATURES` contain the feature name? Does
   `FeatureFlags::check_mount()` produce the correct result for all classes?
3. **Evolve**: Does the TLV type appear in the TLV type registry? Does the
   old-reader skip test pass?
4. **Migrate**: Does the rebake scanner detect old-format records? Is the
   atomic CoW swap verified with a crash test?


## Cross-Cutting Rules

These rules apply across all phases and are non-negotiable:

### R1. No format change without golden vectors

Every new record type or TLV must have golden encode/decode pairs committed
before implementation. The golden vectors are the specification's executable
truth. See #1185.

### R2. Feature flag before format

A record family must be gated by a feature flag registered in
`CANONICAL_V1_FEATURES` before it can appear on media. This ensures the
mount algorithm can always decide whether a dataset is safe to open.
See #1223.

### R3. Forward compat by default

Any engine must be able to read older-format datasets. Write compatibility
is governed by `ro_compat` (read-only) and `incompat` (refuse). The TLV
skip mechanism ensures forward compat for unknown extensions. See #1220 §2.

### R4. Python oracle mirror

Every Rust format implementation must have a Python reference implementation
between them. See #1236 and #1235.

### R5. Append-only golden vectors

Golden vectors are never modified once committed. New vectors are added for
new capabilities. This ensures regression detection: if a code change breaks
an existing golden vector, the breakage is caught immediately.

### R6. One-way feature enablement

Feature flags are one-way: once enabled for a dataset, they cannot be
disabled. This prevents the "enabled, wrote data, disabled, data becomes
unreadable" failure mode.

---

## Format Change Proposal Template

Every proposed format change must use this checklist in its design doc
or issue description:

```markdown
## Format Change Proposal: <short-name>

### Phase 1: Define
- [ ] Record type / TLV type specified with field layout table
- [ ] Encoding rules documented (byte order, alignment, checksum domain)
- [ ] Feature flag name proposed (reverse-DNS, registered in CANONICAL_V1_FEATURES)
- [ ] Feature class justified (compat / ro_compat / incompat)
- [ ] Golden vectors committed (≥3 encode/decode pairs per record type)
- [ ] Python reference implementation updated

### Phase 2: Gate
- [ ] Feature name merged into CANONICAL_V1_FEATURES constant
- [ ] FeatureFlags::check_mount() handles the new feature correctly
- [ ] Unit tests: all mount scenarios pass

### Phase 3: Evolve
- [ ] TLV type registered in TLV type registry (if applicable)
- [ ] Encode/decode implemented with old-reader skip test
- [ ] TLV ordering invariant checked at encode time
- [ ] TLV size limit enforced at decode time

### Phase 4: Migrate
- [ ] Rebake scanner detects old-format records (if migration needed)
- [ ] Rebake converter produces new-format records correctly
- [ ] Atomic pointer swap verified (CoW update)
- [ ] Crash recovery test: crash mid-rebake, restart, verify consistency

- [ ] All golden vectors pass
- [ ] Trace oracle replay passes (Python ↔ Rust)
- [ ] Crash injection at format boundaries passes (≥3 crash seeds)
- [ ] Online verifier coverage updated
```

---

## Tradeoffs and Design Rationale

### T1. Single V1 vs. Per-Record Versioning

**Decision**: All on-media records use a single V1 family with TLV extensions,
rather than per-record version headers.

**Rationale**: Per-record versioning creates an N×M compatibility matrix: N
record types × M versions each. After three format revisions across six
record families, you have 18 decoder paths. The TLV approach collapses this
to one code path per record family: parse the fixed prefix, then walk TLVs.
Unknown TLVs are mechanically skipped.

**Tradeoff**: TLV adds 4 bytes per extension (type + length overhead) and
requires an ordered walk at decode time. We accept this because extensions
are rare (0–3 TLVs per record), the walk is O(T) with T ≤ ~10 in practice,
and the forward-compat guarantee is worth the marginal decode cost.

**Alternative considered**: Protobuf-style field numbers with wire types.
Rejected because protobuf varints violate the fixed-width LE scalar law
(P2-03 §1.2) and field-number allocation requires central coordination.

### T2. Three-Class Feature Model vs. Single Bitmap

**Decision**: Three feature classes (`compat`, `ro_compat`, `incompat`)
rather than a single feature bitmap.

**Rationale**: A single bitmap forces every flag to carry its own class
semantics in-band. The three-class model separates the mount decision from
the per-feature data: the mount check reads three B+tree roots, iterates
each tree, and classifies the result. Unknown `incompat` features are
discovered before any data interpretation begins.

**Tradeoff**: Three B+trees use more space than a single packed bitmap
(3 × 8-byte root pointers vs. 3 × 8-byte bitmaps). However, B+trees
support sparse feature sets (most datasets have 0–5 features enabled)
and allow feature names up to 127 bytes.

**Alternative considered**: ZFS-style feature flags (single on-disk
bitmap with `features_for_read` mask). Rejected because the ZFS model
ties feature identity to a pool version number, making cross-implementation
feature gating implicit. TideFS makes feature gating explicit via named flags.

### T3. Background Rebake vs. Online Conversion

**Decision**: Rebake runs as a background job, not inline on every write.

**Rationale**: Online conversion (convert on write) adds latency to every
foreground operation. Background rebake decouples migration cost from
user-visible latency. The tradeoff is that old-format data persists until
rebake catches up, which we accept for the latency win.

**Alternative considered**: Convert-on-write with a write amplification
budget. Rejected because it makes write latency unpredictable and couples
format migration to the foreground I/O path.

### T4. Append-Only Golden Vectors vs. Versioned Vectors

**Decision**: Golden vectors are append-only; they are never modified.

**Rationale**: Modifying a golden vector would silently change the
correctness reference, masking regressions. Append-only ensures that every
golden vector ever committed remains a valid regression test.


**Decision**: A Python reference implementation is required alongside every
Rust format implementation.

**Rationale**: A second implementation in a different language catches bugs
that unit tests in the same language miss. The Python implementation serves
as the oracle: if Rust and Python produce different output for the same
input, at least one is wrong. This is especially valuable for encoding
rules (endianness, alignment, checksum computation) where off-by-one or
byte-order errors are common.

**Tradeoff**: Maintaining two implementations doubles the implementation
burden. We accept this because the Python oracle is intentionally simpler
(no performance requirements, no concurrency) and serves as executable
specification.

---

## Dependency Graph

The format lifecycle issues form a DAG. This section maps the dependencies
so that implementers can determine the correct order of work.

```
                          ┌──────────────────────┐
                          │  #1238 (this doc)    │
                          │  Meta-framework      │
                          └──────┬───────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼────────┐ ┌──────▼──────┐  ┌────────▼────────┐
    │ #1220 Record     │ │ #1223       │  │ #1236 RFP-Core  │
    │ family strategy  │ │ Feature flags│  │ Python oracle   │
    │ (Phase 1, 3)     │ │ (Phase 2)   │  │ (cross-cutting) │
    └────────┬─────────┘ └──────┬──────┘  └────────┬────────┘
             │                  │                  │
    ┌────────▼────────┐         │         ┌────────▼────────┐
    │ #1225 Extent map│◄────────┘         │ #1235 Trace     │
    │ tristate model  │                   │ oracle (Phase 5)│
    │ (example family)│                   └────────┬────────┘
    └────────┬────────┘                            │
             │                           ┌─────────▼─────────┐
    ┌────────▼────────┐                  │ #1185 Golden       │
    │ #1222 Rebake    │                  │ vectors (Phase 1,5)│
    │ (Phase 4)       │                  └───────────────────┘
    └─────────────────┘
             │
    ┌────────▼────────┐
    │ #1224 Torn-commit│
    │ recovery (Phase 5)│
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │ #1230 Crash     │
    │ injection harness│
    └─────────────────┘
```

### Dependency rules

| Rule | Description |
|---|---|
| D1 | #1238 must be complete before any format change can claim lifecycle compliance |
| D2 | #1223 must be implemented before any feature-gated format can appear on media |
| D3 | #1220 must define a record family before #1225 can implement it |
| D5 | #1222 (rebake) must be complete before #1224 (torn-commit) can test crash recovery at migration boundaries |
| D7 | #1185 (golden vectors) is a dependency of all format change proposals (R1) |

### Milestone alignment

This lifecycle framework maps to the DESIGN-M1 milestone layers:

- **Layer 0** (Meta): #1238 (this doc), #1236 (RFP-Core)
- **Layer 1** (Format & Storage): #1220, #1223, #1225, #1224, #1222
- **Layer 2** (Transaction): #1267 (COMMIT_GROUP state machine, which gates write-path format changes)

---

## Pipeline Algorithm: End-to-End Format Change

This section describes the complete algorithm that a format change must
binds all five phases into a single workflow.

### Algorithm

```rust
fn format_change_lifecycle(proposal: FormatChangeProposal) -> Result<(), LifecycleError> {
    // ── Phase 1: Define ────────────────────────────────────────────
    // 1a. Write the field layout table for each record type.
    let field_layout = define_field_layout(&proposal.record_types)?;

    // 1b. Register the feature name in CANONICAL_V1_FEATURES.
    let feature_name = FeatureName::new(&proposal.feature_name)
        .ok_or(LifecycleError::InvalidFeatureName)?;
    assert!(CANONICAL_V1_FEATURES.contains(&feature_name.as_str()));

    // 1c. Justify the feature class using the decision tree.
    let feature_class = classify_feature(&proposal);

    // 1d. Commit golden vectors (min 3 per record type).
    for record_type in &proposal.record_types {
        commit_golden_vectors(record_type, /* min_pairs */ 3)?;
    }

    // 1e. Update Python reference implementation.
    update_python_oracle(&proposal)?;

    // ── Phase 2: Gate ──────────────────────────────────────────────
    // 2a. The feature flag must be handled by the mount algorithm.
    let mut flags = FeatureFlags::new();
    flags.enable_feature(feature_name, feature_class)?;

    // 2b. Verify all mount scenarios.
    assert_eq!(flags.check_mount(), MountCheckResult::OkRw);
    match feature_class {
        FeatureClass::Incompat => assert!(unknown_flags.check_mount().is_refused()),
        FeatureClass::RoCompat => assert!(unknown_flags.check_mount().is_read_only()),
        FeatureClass::Compat  => assert_eq!(unknown_flags.check_mount(), MountCheckResult::OkRw),
    }

    // ── Phase 3: Evolve (if TLVs defined) ──────────────────────────
    if !proposal.tlvs.is_empty() {
        for tlv in &proposal.tlvs {
            register_tlv_type(tlv)?;
        }
        // Old-reader skip test: encode with TLVs, decode with old reader,
        // verify TLVs are silently skipped and fixed prefix is intact.
        test_old_reader_skip(&proposal)?;
        // TLV ordering invariant: sorted by type code ascending.
        test_tlv_ordering_invariant(&proposal)?;
        // TLV size limit: total TLV area ≤ 4096 bytes.
        test_tlv_size_limit(&proposal)?;
    }

    // ── Phase 4: Migrate (if old-format data exists) ───────────────
    if proposal.requires_migration {
        let old_records = rebake_scanner::scan(&proposal)?;
        let plan = rebake_planner::plan(&old_records, &proposal.target_format)?;
        for chunk in plan.chunks() {
            rebake_converter::convert_chunk(chunk)?;
        }
        test_atomic_cow_swap(&proposal)?;
        crash_injection_test(&proposal, /* seeds */ 3)?;
    }

    run_golden_vector_tests(&proposal)?;

    let rust_trace = TraceRunner::new()?.run_trace(&proposal.rust_trace_path)?;
    let python_trace = TraceRunner::new()?.run_trace(&proposal.python_trace_path)?;
    assert_trace_equivalence(&rust_trace, &python_trace)?;

    for seed in 0..3 {
        commit_commit_group_with_format_change(&proposal)?;
        inject_crash_at_boundary(seed)?;
        recover_and_verify_consistency()?;
    }

    update_online_verifier_coverage(&proposal)?;

    Ok(())
}
```

### Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| Golden vector mismatch | CI on every push | Fix encoder/decoder; golden vectors are append-only |
| Feature flag not registered | `const` assertion at compile time | Register in `CANONICAL_V1_FEATURES` |
| Mount gate regression | Unit test `check_mount` scenarios | Fix mount algorithm, add test for the specific scenario |
| TLV ordering violation | Decode-time check | Fix encoder; TLVs must be sorted at encode |
| Rebake crash mid-conversion | COMMIT_GROUP log replay on recovery | Resume rebake from last committed cursor |
| Trace oracle divergence | Cross-implementation replay | Fix whichever implementation is wrong |

### Performance budget

The lifecycle framework imposes no runtime overhead on the foreground I/O
path. All lifecycle costs are paid at:

- **Design time**: design doc writing, golden vector creation — human cost
- **Mount time**: feature flag check — O(F) where F ≤ ~10 features per dataset
- **Background time**: rebake, online verification — budgeted scheduler ticks


## Lifecycle Integration with Existing Issues

| Issue | Role in lifecycle | Phase |
|---|---|---|
| #1220 | Record family catalogue, TLV rules, encoding spec | 1, 3 |
| #1223 | Feature flag model, mount gating algorithm | 2 |
| #1225 | Extent map tristate: example record family through full lifecycle | 1–5 |
| #1222 | Rebake engine: incremental format migration | 4 |
| #1235 | Trace oracle: cross-implementation semantic equivalence | 5 |
| #1236 | RFP-Core methodology: Python oracle mirror | cross-cutting |
| #1230 | Crash injection harness: deterministic fault injection | 5 |

---

## Implementation Status

| Component | Status | Crate(s) |
|---|---|---|
| Record family catalogue | **design-spec** | `docs/design/on-media-format-strategy.md` |
| Binary schema core (LE, checksum, alignment) | **implemented-source** | `tidefs-binary_schema-core` |
| Binary schema framing (envelope, section, chunk) | **implemented-source** | `tidefs-binary_schema-framing` |
| Binary schema checksum (crc32c, blake3) | **implemented-source** | `tidefs-binary_schema-checksum` |
| Feature flag types + registry | **implemented-source** | `tidefs-types-dataset-feature-flags-core` |
| Feature flag runtime + mount gating | **implemented-source** | `tidefs-dataset-feature-flags` |
| TLV encoding rules | **design-spec** | (inside `docs/design/on-media-format-strategy.md` §2) |
| Extent map tristate (example record family) | **implemented-source** | `tidefs-extent-map`, `tidefs-types-extent-map-core` |
| Unified format lifecycle (this document) | **design-spec** | `docs/design/unified-on-media-format-lifecycle.md` |
| Rebake engine | **deferred** | — (integration point: `tidefs-background-scheduler`) |
| Golden vectors (formalized spec) | **partial** | Unit tests exist; formal golden-vector framework deferred |
| Trace oracle | **implemented-source** | `tidefs-trace-oracle` |
| Crash injection harness | **design-spec** | `docs/design/deterministic-crash-injection-harness.md` |
| Python oracle mirror | **deferred** | `python/tidefs_format/` (reference implementation) |
| Online verifier | **implemented-source** | `tidefs-online-verifier` |

---

## References

- `docs/design/on-media-format-strategy.md` — V1 record family catalogue
- `docs/V1_EXTENT_MAP_TRISTATE_MODEL_DESIGN.md` — Extent map tristate model
- `docs/DATASET_FEATURE_FLAGS_DESIGN.md` — Feature flag design
- `docs/design/deterministic-crash-injection-harness.md` — Crash injection harness
- `crates/tidefs-types-dataset-feature-flags-core/src/lib.rs` — Feature flag type authority
- `crates/tidefs-dataset-feature-flags/src/lib.rs` — Feature flag runtime
- `crates/tidefs-trace-oracle/src/lib.rs` — Trace oracle replay engine
- `crates/tidefs-online-verifier/src/lib.rs` — Online verifier
- `crates/tidefs-binary_schema-core/src/lib.rs` — Binary schema core (endian, alignment, checksum)
- P2-03 — Canonical binary encode/decode/endian/checksum law
